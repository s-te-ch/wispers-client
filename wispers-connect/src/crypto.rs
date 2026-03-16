//! Cryptographic primitives: Ed25519 signing keys, X25519 key exchange,
//! and pairing codes/secrets used during the activation protocol.

use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{Signature, SigningKey, Signer, VerifyingKey, Verifier};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// Length of a pairing secret in bytes.
const PAIRING_SECRET_LEN: usize = 7;

/// Length of a nonce in bytes.
const NONCE_LEN: usize = 16;

/// Ed25519 signing keypair derived from the root key.
#[derive(Clone)]
pub struct SigningKeyPair {
    signing_key: SigningKey,
}

impl SigningKeyPair {
    /// Derive a signing keypair from the root key using HKDF.
    pub fn derive_from_root_key(root_key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"wispers-connect-v1"), root_key);
        let mut signing_seed = [0u8; 32];
        hk.expand(b"signing-key", &mut signing_seed)
            .expect("32 bytes is valid for HKDF-SHA256");

        let signing_key = SigningKey::from_bytes(&signing_seed);
        Self { signing_key }
    }

    /// Get the public key in SPKI (X.509 SubjectPublicKeyInfo) DER format.
    pub fn public_key_spki(&self) -> Vec<u8> {
        self.signing_key
            .verifying_key()
            .to_public_key_der()
            .expect("Ed25519 SPKI encoding cannot fail")
            .to_vec()
    }

    /// Get the raw public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }
}

/// X25519 key exchange keypair derived from the root key.
///
/// This stores the seed rather than the secret directly, since
/// `X25519StaticSecret` doesn't implement Clone. The secret is
/// derived on-demand for cryptographic operations.
#[derive(Clone)]
pub struct X25519KeyPair {
    seed: [u8; 32],
}

impl X25519KeyPair {
    /// Derive an X25519 keypair from the root key using HKDF.
    pub fn derive_from_root_key(root_key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"wispers-connect-v1"), root_key);
        let mut seed = [0u8; 32];
        hk.expand(b"x25519-key", &mut seed)
            .expect("32 bytes is valid for HKDF-SHA256");

        Self { seed }
    }

    /// Get the secret (derived from seed).
    fn secret(&self) -> X25519StaticSecret {
        X25519StaticSecret::from(self.seed)
    }

    /// Get the public key as raw bytes.
    pub fn public_key(&self) -> [u8; 32] {
        X25519PublicKey::from(&self.secret()).to_bytes()
    }

    /// Perform Diffie-Hellman key exchange with a peer's public key.
    /// Returns the shared secret.
    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer_public = X25519PublicKey::from(*peer_public);
        self.secret().diffie_hellman(&peer_public).to_bytes()
    }
}

/// Verify a signature using a public key in SPKI DER format.
pub fn verify_signature_spki(spki: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_public_key_der(spki) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    verifying_key.verify(message, &sig).is_ok()
}

//-- Pairing secrets -------------------------------------------------------------------------------

/// A pairing secret for device-to-device activation.
#[derive(Clone)]
pub struct PairingSecret {
    bytes: [u8; PAIRING_SECRET_LEN],
}

impl PairingSecret {
    /// Generate a new random pairing secret.
    pub fn generate() -> Self {
        let mut bytes = [0u8; PAIRING_SECRET_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        // Round-trip through base36 to ensure consistent encoding
        let base36 = encode_base36(&bytes);
        let bytes = decode_base36(&base36).expect("just encoded");
        Self { bytes }
    }

    /// Parse a pairing secret from base36 encoding.
    pub fn from_base36(s: &str) -> Result<Self, PairingSecretError> {
        let bytes = decode_base36(s)?;
        Ok(Self { bytes })
    }

    /// Get the base36 encoding (10 lowercase characters).
    pub fn to_base36(&self) -> String {
        encode_base36(&self.bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derive the MAC key for pairing message authentication.
    fn derive_mac_key(&self) -> [u8; 32] {
        // Match Go implementation: HMAC(secret, salt || info)
        let mut mac = HmacSha256::new_from_slice(&self.bytes)
            .expect("HMAC can take any key size");
        mac.update(b"wispers-pairing-v1");     // salt
        mac.update(b"wispers-pairing-v1|mac"); // info
        let result = mac.finalize();
        result.into_bytes().into()
    }

    /// Compute HMAC for a pairing message payload.
    pub fn compute_mac(&self, payload: &[u8]) -> Vec<u8> {
        let key = self.derive_mac_key();
        let mut mac = HmacSha256::new_from_slice(&key)
            .expect("HMAC can take any key size");
        mac.update(payload);
        let result = mac.finalize();
        // Truncate to 16 bytes (128 bits) to match Go implementation
        result.into_bytes()[..16].to_vec()
    }

    /// Verify HMAC for a pairing message payload.
    pub fn verify_mac(&self, payload: &[u8], tag: &[u8]) -> bool {
        let expected = self.compute_mac(payload);
        constant_time_eq(&expected, tag)
    }
}

/// Error parsing a pairing secret.
#[derive(Debug, thiserror::Error)]
pub enum PairingSecretError {
    #[error("invalid length: expected 10 characters")]
    InvalidLength,
    #[error("invalid base36 character")]
    InvalidCharacter,
}

/// Encode bytes as 10 lowercase base36 characters.
fn encode_base36(bytes: &[u8]) -> String {
    let n = BigUint::from_bytes_be(bytes);
    let mut s = n.to_str_radix(36);
    // Pad to 10 characters
    while s.len() < 10 {
        s.insert(0, '0');
    }
    // Truncate if too long (most significant digits)
    if s.len() > 10 {
        s = s[s.len() - 10..].to_string();
    }
    s
}

/// Decode 10 base36 characters to bytes.
fn decode_base36(s: &str) -> Result<[u8; PAIRING_SECRET_LEN], PairingSecretError> {
    if s.len() != 10 {
        return Err(PairingSecretError::InvalidLength);
    }
    let n = BigUint::parse_bytes(s.as_bytes(), 36)
        .ok_or(PairingSecretError::InvalidCharacter)?;
    let mut bytes = n.to_bytes_be();
    // Pad to 7 bytes
    while bytes.len() < PAIRING_SECRET_LEN {
        bytes.insert(0, 0);
    }
    let mut result = [0u8; PAIRING_SECRET_LEN];
    result.copy_from_slice(&bytes);
    Ok(result)
}

//-- Pairing code (node_number + secret) -----------------------------------------------------------

/// A pairing code combining node number and secret for display/entry.
pub struct PairingCode {
    pub node_number: i32,
    pub secret: PairingSecret,
}

impl PairingCode {
    /// Create a new pairing code.
    pub fn new(node_number: i32, secret: PairingSecret) -> Self {
        Self { node_number, secret }
    }

    /// Format as "node_number-base36secret" for display.
    pub fn format(&self) -> String {
        format!("{}-{}", self.node_number, self.secret.to_base36())
    }

    /// Parse from "node_number-base36secret" format.
    pub fn parse(s: &str) -> Result<Self, PairingCodeError> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err(PairingCodeError::InvalidFormat);
        }
        let node_number: i32 = parts[0]
            .parse()
            .map_err(|_| PairingCodeError::InvalidNodeNumber)?;
        let secret = PairingSecret::from_base36(parts[1])
            .map_err(|e| PairingCodeError::InvalidSecret(e))?;
        Ok(Self { node_number, secret })
    }
}

/// Error parsing a pairing code.
#[derive(Debug, thiserror::Error)]
pub enum PairingCodeError {
    #[error("invalid format: expected 'node_number-secret'")]
    InvalidFormat,
    #[error("invalid node number")]
    InvalidNodeNumber,
    #[error("invalid secret: {0}")]
    InvalidSecret(PairingSecretError),
}

//-- Nonces ----------------------------------------------------------------------------------------

/// Generate a random nonce for pairing.
pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

//-- Helpers ---------------------------------------------------------------------------------------

/// Constant-time equality comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base36_roundtrip() {
        let secret = PairingSecret::generate();
        let encoded = secret.to_base36();
        assert_eq!(encoded.len(), 10);
        let decoded = PairingSecret::from_base36(&encoded).unwrap();
        assert_eq!(secret.bytes, decoded.bytes);
    }

    #[test]
    fn test_pairing_code_roundtrip() {
        let code = PairingCode::new(42, PairingSecret::generate());
        let formatted = code.format();
        let parsed = PairingCode::parse(&formatted).unwrap();
        assert_eq!(code.node_number, parsed.node_number);
        assert_eq!(code.secret.bytes, parsed.secret.bytes);
    }

    #[test]
    fn test_mac_verification() {
        let secret = PairingSecret::generate();
        let payload = b"test payload";
        let mac = secret.compute_mac(payload);
        assert!(secret.verify_mac(payload, &mac));
        assert!(!secret.verify_mac(b"different payload", &mac));
    }

    #[test]
    fn test_signing_key_derivation() {
        let root_key = [42u8; 32];
        let kp1 = SigningKeyPair::derive_from_root_key(&root_key);
        let kp2 = SigningKeyPair::derive_from_root_key(&root_key);
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_signature_roundtrip() {
        let root_key = [42u8; 32];
        let kp = SigningKeyPair::derive_from_root_key(&root_key);
        let message = b"test message";
        let signature = kp.sign(message);
        let spki = kp.public_key_spki();
        assert!(verify_signature_spki(&spki, message, &signature));
        assert!(!verify_signature_spki(&spki, b"wrong message", &signature));
    }

    #[test]
    fn test_x25519_derivation_deterministic() {
        let root_key = [42u8; 32];
        let kp1 = X25519KeyPair::derive_from_root_key(&root_key);
        let kp2 = X25519KeyPair::derive_from_root_key(&root_key);
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_x25519_different_roots_different_keys() {
        let kp1 = X25519KeyPair::derive_from_root_key(&[1u8; 32]);
        let kp2 = X25519KeyPair::derive_from_root_key(&[2u8; 32]);
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_x25519_dh_shared_secret() {
        // Two parties derive keypairs from different root keys
        let alice = X25519KeyPair::derive_from_root_key(&[1u8; 32]);
        let bob = X25519KeyPair::derive_from_root_key(&[2u8; 32]);

        // Each performs DH with the other's public key
        let alice_shared = alice.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&alice.public_key());

        // They should arrive at the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }
}
