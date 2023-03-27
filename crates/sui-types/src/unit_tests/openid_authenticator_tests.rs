// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    base_types::SuiAddress,
    crypto::{get_key_pair_from_rng, DefaultHash, Signature, SignatureScheme, SuiKeyPair},
    openid_authenticator::{
        MaskedContent, OAuthProviderContent, OpenIdAuthenticator, ProofPoints, PublicInputs,
        SerializedVerifyingKey,
    },
    signature::{AuthenticatorTrait, GenericSignature},
    utils::make_transaction,
};
use fastcrypto::hash::HashFunction;
use fastcrypto::rsa::{Base64UrlUnpadded, Encoding as OtherEncoding};
use fastcrypto::{
    encoding::{Base64, Encoding},
    traits::ToFromBytes,
};
use rand::{rngs::StdRng, SeedableRng};
use shared_crypto::intent::{Intent, IntentMessage, IntentScope};

pub fn keys() -> Vec<SuiKeyPair> {
    let mut seed = StdRng::from_seed([0; 32]);
    let kp1: SuiKeyPair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut seed).1);
    let kp2: SuiKeyPair = SuiKeyPair::Secp256k1(get_key_pair_from_rng(&mut seed).1);
    let kp3: SuiKeyPair = SuiKeyPair::Secp256r1(get_key_pair_from_rng(&mut seed).1);
    vec![kp1, kp2, kp3]
}

#[test]
fn openid_authenticator_scenarios() {
    let keys = keys();
    let foundation_key = &keys[0];
    let user_key = &keys[1];

    let vk = SerializedVerifyingKey::from_fp("./src/unit_tests/google.vkey");

    let public_inputs = PublicInputs::from_fp("./src/unit_tests/public.json");

    let proof_points = ProofPoints::from_fp("./src/unit_tests/google.proof");

    let mut hasher = DefaultHash::default();
    hasher.update([SignatureScheme::OpenIdAuthenticator.flag()]);
    hasher.update(&vk.vk_gamma_abc_g1);
    hasher.update(&vk.alpha_g1_beta_g2);
    hasher.update(&vk.gamma_g2_neg_pc);
    hasher.update(&vk.delta_g2_neg_pc);
    let user_address = SuiAddress::from_bytes(hasher.finalize().digest).unwrap();

    // Create an example bulletin with 2 keys from Google.
    let example_bulletin = vec![
        OAuthProviderContent {
            iss: "https://accounts.google.com".to_string(),
            kty: "RSA".to_string(),
            kid: "986ee9a3b7520b494df54fe32e3e5c4ca685c89d".to_string(),
            e: "AQAB".to_string(),
            n: "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ".to_string(),
            alg: "RS256".to_string(),
        }
    ];

    // Sign the bulletin content with the sui foundation key as a personal message.
    let bulletin_sig = Signature::new_secure(
        &IntentMessage::new(
            Intent::sui_app(IntentScope::PersonalMessage),
            example_bulletin.clone(),
        ),
        foundation_key,
    );

    // Sign the user transaction with the user's ephemeral key.
    let tx = make_transaction(user_address, user_key, Intent::sui_transaction());
    let s = match tx.inner().tx_signatures.first().unwrap() {
        GenericSignature::Signature(s) => s,
        _ => panic!("Expected a signature"),
    };

    let authenticator = OpenIdAuthenticator {
        vk,
        public_inputs,
        proof_points,
        masked_content: MaskedContent::new("=======================================================================================================eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20i================================================================LCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20i=========================================================================================================================================================================".to_string()),
        jwt_signature: Base64UrlUnpadded::decode_vec("cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw").unwrap(),
        user_signature: s.clone(),
        bulletin_signature: bulletin_sig,
        bulletin: example_bulletin
    };
    assert!(authenticator
        .verify_secure_generic(
            &IntentMessage::new(
                Intent::sui_transaction(),
                tx.into_data().transaction_data().clone()
            ),
            user_address,
            Some(0)
        )
        .is_ok());
}

#[test]
fn test_authenticator_failure() {}

#[test]
fn test_serde_roundtrip() {}

#[test]
fn test_open_id_authenticator_address() {}
