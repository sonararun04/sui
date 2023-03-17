// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::encoding::{Encoding, Hex};
use rand::rngs::OsRng;
use rand::seq::IteratorRandom;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use sui_config::utils;
use sui_json_rpc_types::{SuiObjectDataOptions, SuiObjectResponseQuery};
use sui_keys::keystore::AccountKeystore;
use sui_keys::keystore::Keystore;
use sui_rosetta::operations::Operations;
use sui_rosetta::types::{
    ConstructionCombineRequest, ConstructionCombineResponse, ConstructionMetadataRequest,
    ConstructionMetadataResponse, ConstructionPayloadsRequest, ConstructionPayloadsResponse,
    ConstructionPreprocessRequest, ConstructionPreprocessResponse, ConstructionSubmitRequest,
    NetworkIdentifier, Signature, SignatureType, SuiEnv, TransactionIdentifierResponse,
};
use sui_rosetta::{RosettaOfflineServer, RosettaOnlineServer};
use sui_sdk::SuiClient;
use sui_types::base_types::{ObjectID, ObjectRef, SuiAddress};
use sui_types::crypto::SuiSignature;
use tokio::task::JoinHandle;

pub async fn start_rosetta_test_server(
    client: SuiClient,
    dir: &Path,
) -> (RosettaClient, Vec<JoinHandle<hyper::Result<()>>>) {
    let online_server =
        RosettaOnlineServer::new(SuiEnv::LocalNet, client, &dir.join("rosetta_data"));
    let offline_server = RosettaOfflineServer::new(SuiEnv::LocalNet);
    let local_ip = utils::get_local_ip_for_tests().to_string();
    let port = utils::get_available_port(&local_ip);
    let rosetta_address = format!("{}:{}", local_ip, port);
    let online_handle = online_server.serve(SocketAddr::from_str(&rosetta_address).unwrap());
    let offline_port = utils::get_available_port(&local_ip);
    let offline_address = format!("{}:{}", local_ip, offline_port);
    let offline_handle = offline_server.serve(SocketAddr::from_str(&offline_address).unwrap());

    // allow rosetta to process the genesis block.
    tokio::task::yield_now().await;
    (
        RosettaClient::new(port, offline_port),
        vec![online_handle, offline_handle],
    )
}

pub struct RosettaClient {
    client: Client,
    online_port: u16,
    offline_port: u16,
}

impl RosettaClient {
    fn new(online: u16, offline: u16) -> Self {
        let client = Client::new();
        Self {
            client,
            online_port: online,
            offline_port: offline,
        }
    }
    pub async fn call<R: Serialize, T: DeserializeOwned>(
        &self,
        endpoint: RosettaEndpoint,
        request: &R,
    ) -> T {
        let port = if endpoint.online() {
            self.online_port
        } else {
            self.offline_port
        };
        let response = self
            .client
            .post(format!("http://127.0.0.1:{port}/{endpoint}"))
            .json(&serde_json::to_value(request).unwrap())
            .send()
            .await
            .unwrap();
        let json: Value = response.json().await.unwrap();
        if let Ok(v) = serde_json::from_value(json.clone()) {
            v
        } else {
            panic!("Failed to deserialize json value: {json:#?}")
        }
    }

    /// rosetta construction e2e flow, see https://www.rosetta-api.org/docs/flow.html#construction-api
    pub async fn rosetta_flow(
        &self,
        operations: Operations,
        keystore: &Keystore,
    ) -> TransactionIdentifierResponse {
        let network_identifier = NetworkIdentifier {
            blockchain: "sui".to_string(),
            network: SuiEnv::LocalNet,
        };
        // Preprocess
        let preprocess: ConstructionPreprocessResponse = self
            .call(
                RosettaEndpoint::Preprocess,
                &ConstructionPreprocessRequest {
                    network_identifier: network_identifier.clone(),
                    operations: operations.clone(),
                    metadata: None,
                },
            )
            .await;
        println!("Preprocess : {preprocess:?}");
        // Metadata
        let metadata: ConstructionMetadataResponse = self
            .call(
                RosettaEndpoint::Metadata,
                &ConstructionMetadataRequest {
                    network_identifier: network_identifier.clone(),
                    options: preprocess.options,
                    public_keys: vec![],
                },
            )
            .await;
        println!("Metadata : {metadata:?}");
        // Payload
        let payloads: ConstructionPayloadsResponse = self
            .call(
                RosettaEndpoint::Payloads,
                &ConstructionPayloadsRequest {
                    network_identifier: network_identifier.clone(),
                    operations,
                    metadata: Some(metadata.metadata),
                    public_keys: vec![],
                },
            )
            .await;
        println!("Payload : {payloads:?}");
        // Combine
        let signing_payload = payloads.payloads.first().unwrap();
        let bytes = Hex::decode(&signing_payload.hex_bytes).unwrap();
        let signer = signing_payload.account_identifier.address;
        let signature = AccountKeystore::sign(keystore, &signer, &bytes).unwrap();
        let public_key = AccountKeystore::get_key(keystore, &signer)
            .unwrap()
            .public();
        let combine: ConstructionCombineResponse = self
            .call(
                RosettaEndpoint::Combine,
                &ConstructionCombineRequest {
                    network_identifier: network_identifier.clone(),
                    unsigned_transaction: payloads.unsigned_transaction,
                    signatures: vec![Signature {
                        signing_payload: signing_payload.clone(),
                        public_key: public_key.into(),
                        signature_type: SignatureType::Ed25519,
                        hex_bytes: Hex::from_bytes(SuiSignature::signature_bytes(&signature)),
                    }],
                },
            )
            .await;
        println!("Combine : {combine:?}");
        // Submit
        let submit = self
            .call(
                RosettaEndpoint::Submit,
                &ConstructionSubmitRequest {
                    network_identifier,
                    signed_transaction: combine.signed_transaction,
                },
            )
            .await;
        println!("Submit : {submit:?}");
        submit
    }
}

pub async fn get_random_sui(
    client: &SuiClient,
    sender: SuiAddress,
    except: Vec<ObjectID>,
) -> ObjectRef {
    let coins = client
        .read_api()
        .get_owned_objects(
            sender,
            Some(SuiObjectResponseQuery::new_with_options(
                SuiObjectDataOptions::full_content(),
            )),
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let coin = coins
        .data
        .iter()
        .filter(|&object| {
            let obj = object.object().unwrap();
            obj.clone().type_.unwrap().is_gas_coin() && !except.contains(&obj.object_id)
        })
        .choose(&mut OsRng::default())
        .unwrap();
    // We type checked the gas coin above
    let gas_coin = coin.clone().into_object().unwrap();

    (gas_coin.object_id, gas_coin.version, gas_coin.digest)
}

#[allow(dead_code)]
pub enum RosettaEndpoint {
    Derive,
    Payloads,
    Combine,
    Preprocess,
    Hash,
    Parse,
    List,
    Options,
    Block,
    Balance,
    Coins,
    Transaction,
    Submit,
    Metadata,
    Status,
}

impl RosettaEndpoint {
    pub fn endpoint(&self) -> &str {
        match self {
            RosettaEndpoint::Derive => "construction/derive",
            RosettaEndpoint::Payloads => "construction/payloads",
            RosettaEndpoint::Combine => "construction/combine",
            RosettaEndpoint::Preprocess => "construction/preprocess",
            RosettaEndpoint::Hash => "construction/hash",
            RosettaEndpoint::Parse => "construction/parse",
            RosettaEndpoint::List => "network/list",
            RosettaEndpoint::Options => "network/options",
            RosettaEndpoint::Block => "block",
            RosettaEndpoint::Balance => "account/balance",
            RosettaEndpoint::Coins => "account/coins",
            RosettaEndpoint::Transaction => "block/transaction",
            RosettaEndpoint::Submit => "construction/submit",
            RosettaEndpoint::Metadata => "construction/metadata",
            RosettaEndpoint::Status => "network/status",
        }
    }

    pub fn online(&self) -> bool {
        match self {
            RosettaEndpoint::Derive
            | RosettaEndpoint::Payloads
            | RosettaEndpoint::Combine
            | RosettaEndpoint::Preprocess
            | RosettaEndpoint::Hash
            | RosettaEndpoint::Parse
            | RosettaEndpoint::List
            | RosettaEndpoint::Options => false,
            RosettaEndpoint::Block
            | RosettaEndpoint::Balance
            | RosettaEndpoint::Coins
            | RosettaEndpoint::Transaction
            | RosettaEndpoint::Submit
            | RosettaEndpoint::Metadata
            | RosettaEndpoint::Status => true,
        }
    }
}

impl Display for RosettaEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.endpoint())
    }
}
