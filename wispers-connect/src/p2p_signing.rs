//! Signing helpers for the P2P handshake (`StartConnectionRequest` and
//! `StartConnectionResponse`).
//!
//! Both messages use a signed-envelope layout: the outer wire message carries
//! `signed_payload: bytes` plus `signature: bytes`. The signature is computed
//! over a domain tag concatenated with the payload bytes:
//!
//! ```text
//!     sig = Ed25519(signing_key, DOMAIN_TAG || payload_bytes)
//! ```
//!
//! Separate domain tags for caller and answerer prevent cross-role signature
//! confusion even if the payload encodings happen to overlap structurally.
//!
//! The payload is carried as opaque `bytes` (not a submessage field) because
//! not all protobuf implementations preserve unknown fields across a
//! decode-re-encode cycle. Carrying the payload as raw bytes means verifiers
//! check the exact wire bytes without re-encoding, which keeps payload
//! evolution forward-compatible.

use crate::crypto::SigningKeyPair;
use crate::hub::proto;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use prost::Message;

/// Domain tag prepended to the payload bytes before signing on the caller side.
pub const CALLER_SIG_DOMAIN: &[u8] = b"wispers-connect/p2p-sig/caller/v1\0";

/// Domain tag prepended to the payload bytes before signing on the answerer side.
pub const ANSWERER_SIG_DOMAIN: &[u8] = b"wispers-connect/p2p-sig/answerer/v1\0";

/// Sign a `StartConnectionRequest::Payload` and return a fully-formed
/// `StartConnectionRequest` envelope.
pub fn build_signed_request(
    signing_key: &SigningKeyPair,
    payload: &proto::start_connection_request::Payload,
) -> proto::StartConnectionRequest {
    let payload_bytes = payload.encode_to_vec();
    let signature = signing_key.sign(&build_caller_signing_input(&payload_bytes));
    proto::StartConnectionRequest {
        signed_payload: payload_bytes,
        signature,
    }
}

/// Sign a `StartConnectionResponse::Payload` and return a fully-formed
/// `StartConnectionResponse` envelope.
pub fn build_signed_response(
    signing_key: &SigningKeyPair,
    payload: &proto::start_connection_response::Payload,
) -> proto::StartConnectionResponse {
    let payload_bytes = payload.encode_to_vec();
    let signature = signing_key.sign(&build_answerer_signing_input(&payload_bytes));
    proto::StartConnectionResponse {
        signed_payload: payload_bytes,
        signature,
    }
}

/// Verify a caller's signature on a `StartConnectionRequest` and decode
/// the inner payload.
///
/// Verification is performed against the raw `signed_payload` bytes from
/// the wire, then the bytes are decoded — never the other way around
/// (see module-level docs for why).
pub fn verify_request(
    request: &proto::StartConnectionRequest,
    caller_public_key_spki: &[u8],
) -> Result<proto::start_connection_request::Payload, SigVerifyError> {
    let key = VerifyingKey::from_public_key_der(caller_public_key_spki)
        .map_err(|_| SigVerifyError::InvalidKey)?;
    let sig = parse_signature(&request.signature)?;
    key.verify(&build_caller_signing_input(&request.signed_payload), &sig)
        .map_err(|_| SigVerifyError::SignatureMismatch)?;
    proto::start_connection_request::Payload::decode(request.signed_payload.as_slice())
        .map_err(|_| SigVerifyError::PayloadDecode)
}

/// Verify an answerer's signature on a `StartConnectionResponse` and
/// decode the inner payload.
pub fn verify_response(
    response: &proto::StartConnectionResponse,
    answerer_public_key_spki: &[u8],
) -> Result<proto::start_connection_response::Payload, SigVerifyError> {
    let key = VerifyingKey::from_public_key_der(answerer_public_key_spki)
        .map_err(|_| SigVerifyError::InvalidKey)?;
    let sig = parse_signature(&response.signature)?;
    key.verify(
        &build_answerer_signing_input(&response.signed_payload),
        &sig,
    )
    .map_err(|_| SigVerifyError::SignatureMismatch)?;
    proto::start_connection_response::Payload::decode(response.signed_payload.as_slice())
        .map_err(|_| SigVerifyError::PayloadDecode)
}

#[derive(Debug, thiserror::Error)]
pub enum SigVerifyError {
    #[error("invalid public key encoding")]
    InvalidKey,
    #[error("signature does not match")]
    SignatureMismatch,
    #[error("could not decode signed payload")]
    PayloadDecode,
}

/// Build the byte string that the caller signs: domain tag || payload bytes.
fn build_caller_signing_input(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CALLER_SIG_DOMAIN.len() + payload.len());
    buf.extend_from_slice(CALLER_SIG_DOMAIN);
    buf.extend_from_slice(payload);
    buf
}

/// Build the byte string that the answerer signs: domain tag || payload bytes.
fn build_answerer_signing_input(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ANSWERER_SIG_DOMAIN.len() + payload.len());
    buf.extend_from_slice(ANSWERER_SIG_DOMAIN);
    buf.extend_from_slice(payload);
    buf
}

fn parse_signature(bytes: &[u8]) -> Result<Signature, SigVerifyError> {
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| SigVerifyError::SignatureMismatch)?;
    Ok(Signature::from_bytes(&arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKeyPair;
    use sha2::{Digest, Sha256};

    fn fixed_signing_key() -> SigningKeyPair {
        SigningKeyPair::derive_from_root_key(&[0x42; 32])
    }

    fn fixed_request_payload() -> proto::start_connection_request::Payload {
        proto::start_connection_request::Payload {
            answerer_node_number: 7,
            caller_x25519_public_key: vec![0xab; 32],
            caller_sdp: "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n".to_string(),
            transport: proto::Transport::Stream as i32,
            stun_turn_config: Some(proto::StunTurnConfig {
                stun_server: "stun.example.test:3478".to_string(),
                turn_server: "turn.example.test:3478".to_string(),
                turn_username: "user".to_string(),
                turn_password: "pass".to_string(),
                expires_at_millis: 1_700_000_000_000,
            }),
        }
    }

    fn fixed_response_payload() -> proto::start_connection_response::Payload {
        proto::start_connection_response::Payload {
            connection_id: 0x1234_5678_9abc_def0_i64,
            answerer_x25519_public_key: vec![0xcd; 32],
            answerer_sdp: "v=0\r\no=- 2 2 IN IP4 0.0.0.0\r\n".to_string(),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut output, b| {
                let _ = write!(output, "{b:02x}");
                output
            })
    }

    /// Tripwire: catches any drift in the caller signing input bytes (e.g.
    /// from a prost upgrade or an inadvertent domain tag change). If this
    /// fails, stop and investigate — a silent change invalidates signatures
    /// from existing peers.
    #[test]
    fn caller_signing_input_golden_hash() {
        let payload_bytes = fixed_request_payload().encode_to_vec();
        let input = build_caller_signing_input(&payload_bytes);
        let expected = "fb63d3e25a17818d38d8d0214a679212baa0a7162c7a7892b3c42504396a245b";
        assert_eq!(hex(&Sha256::digest(&input)), expected);
    }

    /// Tripwire for the answerer side. See caller version for context.
    #[test]
    fn answerer_signing_input_golden_hash() {
        let payload_bytes = fixed_response_payload().encode_to_vec();
        let input = build_answerer_signing_input(&payload_bytes);
        let expected = "1f5fa9d47b66d0ab53e35f2d62ccc948dfe2734790b2f592fa356c4432ff3707";
        assert_eq!(hex(&Sha256::digest(&input)), expected);
    }

    #[test]
    fn round_trip_request() {
        let key = fixed_signing_key();
        let payload = fixed_request_payload();
        let request = build_signed_request(&key, &payload);
        let decoded = verify_request(&request, &key.public_key_spki()).unwrap();
        assert_eq!(decoded.answerer_node_number, payload.answerer_node_number);
        assert_eq!(
            decoded.caller_x25519_public_key,
            payload.caller_x25519_public_key
        );
        assert_eq!(decoded.caller_sdp, payload.caller_sdp);
        assert_eq!(decoded.transport, payload.transport);
        assert_eq!(decoded.stun_turn_config, payload.stun_turn_config);
    }

    #[test]
    fn round_trip_response() {
        let key = fixed_signing_key();
        let payload = fixed_response_payload();
        let response = build_signed_response(&key, &payload);
        let decoded = verify_response(&response, &key.public_key_spki()).unwrap();
        assert_eq!(decoded.connection_id, payload.connection_id);
        assert_eq!(
            decoded.answerer_x25519_public_key,
            payload.answerer_x25519_public_key
        );
        assert_eq!(decoded.answerer_sdp, payload.answerer_sdp);
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let key = fixed_signing_key();
        let mut request = build_signed_request(&key, &fixed_request_payload());
        request.signed_payload[0] ^= 0x01;
        assert!(matches!(
            verify_request(&request, &key.public_key_spki()),
            Err(SigVerifyError::SignatureMismatch)
        ));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let key = fixed_signing_key();
        let mut response = build_signed_response(&key, &fixed_response_payload());
        response.signature[0] ^= 0x01;
        assert!(matches!(
            verify_response(&response, &key.public_key_spki()),
            Err(SigVerifyError::SignatureMismatch)
        ));
    }

    /// A signature produced in the caller role must not verify under the
    /// answerer domain, even on identical payload bytes.
    #[test]
    fn caller_signature_does_not_verify_as_answerer() {
        let key = fixed_signing_key();
        let payload_bytes = fixed_request_payload().encode_to_vec();
        let caller_sig = key.sign(&build_caller_signing_input(&payload_bytes));
        let fake_response = proto::StartConnectionResponse {
            signed_payload: payload_bytes,
            signature: caller_sig,
        };
        assert!(
            matches!(
                verify_response(&fake_response, &key.public_key_spki()),
                Err(SigVerifyError::SignatureMismatch)
            ),
            "caller-signed bytes must not verify under the answerer domain"
        );
    }
}
