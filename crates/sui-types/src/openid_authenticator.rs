// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    base_types::SuiAddress,
    committee::EpochId,
    crypto::{Signature, SuiSignature},
    error::SuiError,
    signature::AuthenticatorTrait,
};
use fastcrypto::rsa::RSASignature;
use fastcrypto::{
    encoding::{Encoding, Hex},
    rsa::RSAPublicKey,
};
use fastcrypto_zkp::bn254::api::{
    serialize_proof_from_file, serialize_public_inputs_from_file, serialize_verifying_key_from_file,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use shared_crypto::intent::Intent;
use shared_crypto::intent::{IntentMessage, IntentScope};
use std::{hash::Hash, str::FromStr};

#[cfg(test)]
#[path = "unit_tests/openid_authenticator_tests.rs"]
mod openid_authenticator_tests;

/// An open id authenticator with all the necessary field.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct OpenIdAuthenticator {
    pub vk: SerializedVerifyingKey,
    pub proof_points: ProofPoints,
    pub public_inputs: PublicInputs,
    pub masked_content: MaskedContent,
    pub jwt_signature: Vec<u8>,
    pub user_signature: Signature,
    pub bulletin_signature: Signature,
    pub bulletin: Vec<OAuthProviderContent>,
}

/// Prepared verifying key in serialized form.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct SerializedVerifyingKey {
    pub vk_gamma_abc_g1: Vec<u8>,
    pub alpha_g1_beta_g2: Vec<u8>,
    pub gamma_g2_neg_pc: Vec<u8>,
    pub delta_g2_neg_pc: Vec<u8>,
}

impl SerializedVerifyingKey {
    pub fn from_fp(path: &str) -> Self {
        let v = serialize_verifying_key_from_file(path);
        let (a, b, c, d) = match (v.get(0), v.get(1), v.get(2), v.get(3)) {
            (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
            _ => panic!("Invalid verifying key file"),
        };
        Self {
            vk_gamma_abc_g1: a.clone(),
            alpha_g1_beta_g2: b.clone(),
            gamma_g2_neg_pc: c.clone(),
            delta_g2_neg_pc: d.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct PublicInputs {
    jwt_hash: Vec<u8>,
    masked_content_hash: Vec<u8>,
    nonce: Vec<u8>,
    eph_public_key: Vec<u8>,
    max_epoch: EpochId,
}

impl PublicInputs {
    pub fn from_fp(path: &str) -> Self {
        let res = serialize_public_inputs_from_file(path);
        let mut jwt_hash = Vec::new();
        jwt_hash.extend_from_slice(&res[0]);
        jwt_hash.extend_from_slice(&res[1]);

        let mut eph_public_key = Vec::new();
        eph_public_key.extend_from_slice(&res[3]);
        eph_public_key.extend_from_slice(&res[4]);
        let byte_array: [u8; 8] = res[5][..8]
            .try_into()
            .expect("Vec<u8> must have at least 8 bytes");

        Self {
            jwt_hash,
            masked_content_hash: res[2].clone(),
            nonce: res[6].clone(),
            eph_public_key,
            max_epoch: u64::from_be_bytes(byte_array),
        }
    }

    pub fn get_jwt_hash(&self) -> &[u8] {
        &self.jwt_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct ProofPoints {
    bytes: Vec<u8>,
}

impl ProofPoints {
    pub fn from_fp(path: &str) -> Self {
        Self {
            bytes: serialize_proof_from_file(path),
        }
    }

    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct MaskedContent {
    header: JWTHeader,
    iss: String,
}

impl MaskedContent {
    pub fn new(_input: String) -> Self {
        Self {
            header: JWTHeader {
                alg: "RS256".to_string(),
                kid: "986ee9a3b7520b494df54fe32e3e5c4ca685c89d".to_string(),
                typ: "JWT".to_string(),
            },
            iss: "https://accounts.google.com".to_string(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct OAuthProviderContent {
    pub iss: String,
    pub kty: String,
    pub kid: String,
    pub e: String,
    pub n: String,
    pub alg: String,
}

#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
struct JWTHeader {
    alg: String,
    kid: String,
    typ: String,
}

impl AuthenticatorTrait for OpenIdAuthenticator {
    /// Verify a proof for an intent message with its sender.
    fn verify_secure_generic<T>(
        &self,
        intent_msg: &IntentMessage<T>,
        author: SuiAddress,
        epoch: Option<EpochId>,
    ) -> Result<(), SuiError>
    where
        T: Serialize,
    {
        println!("!!");
        // Verify the author of the transaction is indeed the hash of the verifying key.
        if author != (&self.vk).into() {
            return Err(SuiError::InvalidAuthenticator);
        }
        println!("Verified author");

        if self.masked_content.iss.to_string() != "https://accounts.google.com"
            || self.masked_content.header.alg.to_string() != "RS256"
            || self.masked_content.header.typ.to_string() != "JWT"
        {
            return Err(SuiError::InvalidAuthenticator);
        }
        println!("Verified masked content");
        if self.public_inputs.max_epoch < epoch.unwrap_or(0) {
            return Err(SuiError::InvalidAuthenticator);
        }
        println!("Verified epoch");
        // Verify the foundation signature indeed commits to the OAuth provider content,
        // that is, a list of valid pubkeys available at https://www.googleapis.com/oauth2/v3/certs.
        if self
            .bulletin_signature
            .verify_secure(
                &IntentMessage::new(
                    Intent::sui_app(IntentScope::PersonalMessage),
                    self.bulletin.clone(),
                ),
                // foundation address, harded coded for now.
                SuiAddress::from_str(
                    "0x73a6b3c33e2d63383de5c6786cbaca231ff789f4c853af6d54cb883d8780adc0",
                )
                .unwrap(),
            )
            .is_err()
        {
            return Err(SuiError::InvalidSignature {
                error: "Bulletin signature verify failed".to_string(),
            });
        }
        println!("Verified bulletin signature");
        // Verify the JWT signature against the OAuth provider public key.
        let sig = RSASignature::from_bytes(&self.jwt_signature)?;
        println!("!!public inputs: {:?}", self.public_inputs);
        let mut verified = false;
        for info in self.bulletin.iter() {
            if info.kid == self.masked_content.header.kid && info.iss == self.masked_content.iss {
                let pk = RSAPublicKey::from_raw_components(
                    &base64_url::decode(&info.n).unwrap(),
                    &base64_url::decode(&info.e).unwrap(),
                )?;
                if pk
                    .verify_prehash(self.public_inputs.get_jwt_hash(), &sig)
                    .is_ok()
                {
                    verified = true;
                }
            }
        }
        println!("Verified JWT signature {:?}", verified);
        if !verified {
            return Err(SuiError::InvalidSignature {
                error: "JWT signature verify failed".to_string(),
            });
        }

        // Verify the user signature over the transaction data
        let res = self.user_signature.verify_secure(intent_msg, author);
        if res.is_err() {
            return Err(SuiError::InvalidSignature {
                error: "User signature verify failed".to_string(),
            });
        }
        print!("Verified user signature {:?}", verified);

        let fake_public_inputs =
            Hex::decode("77e9cbebfa19edd4db4bc403b7bfafeafca3ec759ac7daa8a0dff2b465ea3e05")
                .unwrap();
        match fastcrypto_zkp::bn254::api::verify_groth16_in_bytes(
            &self.vk.vk_gamma_abc_g1,
            &self.vk.alpha_g1_beta_g2,
            &self.vk.gamma_g2_neg_pc,
            &self.vk.delta_g2_neg_pc,
            &fake_public_inputs,
            &self.proof_points.bytes,
        ) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(SuiError::InvalidSignature {
                error: "Groth16 proof verification failed".to_string(),
            }),
        }

        // let public_inputs: Vec<Bn254Fr> = [
        //     &self.hash,
        //     &self.masked_content.content,
        //     self.get_ephemeral_pubkey(),
        //     &self.max_epoch.to_le_bytes(),
        // ]
        // .iter()
        // .flat_map(|x| x.to_field_elements().unwrap())
        // .collect();
        // match fastcrypto_zkp::bn254::api::verify_groth16(
        //     &self.vk_gamma_abc_g1,
        //     &self.alpha_g1_beta_g2,
        //     &self.gamma_g2_neg_pc,
        //     &self.delta_g2_neg_pc,
        //     &public_inputs,
        //     &self.proof_points,
        // ) {
        //     Ok(true) => Ok(()),
        //     Ok(false) | Err(_) => Err(SuiError::InvalidSignature {
        //         error: "Groth16 proof verification failed".to_string(),
        //     }),
        // }
    }
}

impl AsRef<[u8]> for OpenIdAuthenticator {
    fn as_ref(&self) -> &[u8] {
        todo!()
    }
}
