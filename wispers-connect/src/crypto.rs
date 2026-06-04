//! Cryptographic primitives: Ed25519 signing keys, X25519 key exchange,
//! and pairing codes/secrets used during the activation protocol.

use std::time::Duration;

use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// Activation-code lifetime profile. This fixes both the TTL and the entropy:
/// a code's security against offline brute-force is the entropy-vs-window
/// trade, so the two must move together.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TtlProfile {
    /// Short-lived codes for interactive use cases, where we expect the user to
    /// type in the code as soon as they see it.
    #[default]
    Interactive,
    /// Long-lived codes delivered using asynchronous communication like email.
    Asynchronous,
}

impl TtlProfile {
    /// Secret length in bytes.
    fn secret_len(self) -> usize {
        match self {
            TtlProfile::Interactive => 7,  // 56 bits
            TtlProfile::Asynchronous => 9, // 72 bits
        }
    }

    /// Length of the base36 encoding in characters: the smallest that fits
    /// the secret without loss (36^11 ≈ 2^56.9 for 7 bytes, 36^14 ≈ 2^72.4
    /// for 9 bytes).
    fn base36_len(self) -> usize {
        match self {
            TtlProfile::Interactive => 11,
            TtlProfile::Asynchronous => 14,
        }
    }

    /// How long a generated code stays valid. This is the offline
    /// brute-force window the secret length is calibrated against.
    #[must_use]
    pub fn ttl(self) -> Duration {
        match self {
            TtlProfile::Interactive => Duration::from_mins(2),
            TtlProfile::Asynchronous => Duration::from_hours(24),
        }
    }

    /// Recover the profile from a secret's byte length.
    fn from_secret_len(len: usize) -> Option<Self> {
        match len {
            7 => Some(TtlProfile::Interactive),
            9 => Some(TtlProfile::Asynchronous),
            _ => None,
        }
    }

    /// Recover the profile from a base36 code's character length.
    fn from_base36_len(len: usize) -> Option<Self> {
        match len {
            11 => Some(TtlProfile::Interactive),
            14 => Some(TtlProfile::Asynchronous),
            _ => None,
        }
    }
}

/// The new node's deadline on the pairing RPC, calibrated to the weakest
/// (lowest-entropy) [`TtlProfile`], `Interactive`. This guards against the Hub
/// stalling pairing to give itself time to derive the pairing code. The
/// `no_profile_is_weaker_than_interactive` test makes sure we don't introduce
/// a lower-entropy code in the future for which this deadline is too long.
pub(crate) const PAIRING_RPC_DEADLINE: Duration = Duration::from_mins(2);

/// Length of a nonce in bytes.
const NONCE_LEN: usize = 16;

/// Ed25519 signing keypair derived from the root key.
#[derive(Clone)]
pub struct SigningKeyPair {
    signing_key: SigningKey,
}

impl SigningKeyPair {
    /// Derive a signing keypair from the root key using HKDF.
    #[must_use]
    pub fn derive_from_root_key(root_key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"wispers-connect-v1"), root_key);
        let mut signing_seed = [0u8; 32];
        hk.expand(b"signing-key", &mut signing_seed)
            .expect("32 bytes is valid for HKDF-SHA256");

        let signing_key = SigningKey::from_bytes(&signing_seed);
        Self { signing_key }
    }

    /// Get the public key in SPKI (X.509 `SubjectPublicKeyInfo`) DER format.
    #[must_use]
    pub fn public_key_spki(&self) -> Vec<u8> {
        self.signing_key
            .verifying_key()
            .to_public_key_der()
            .expect("Ed25519 SPKI encoding cannot fail")
            .to_vec()
    }

    /// Get the raw public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a message.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }
}

/// X25519 key exchange keypair.
///
/// This stores the seed rather than the secret directly, since
/// `X25519StaticSecret` doesn't implement Clone. The secret is
/// derived on-demand for cryptographic operations.
pub struct X25519KeyPair {
    seed: [u8; 32],
}

impl X25519KeyPair {
    /// Generate an ephemeral X25519 keypair from random bytes.
    pub fn generate_ephemeral() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
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

//-- Pairing secrets -------------------------------------------------------------------------------

/// A pairing secret for device-to-device activation.
#[derive(Clone, Debug)]
pub struct PairingSecret {
    bytes: Vec<u8>,
}

impl PairingSecret {
    /// Generate a new random pairing secret for the given profile.
    pub fn generate(profile: TtlProfile) -> Self {
        let mut bytes = vec![0u8; profile.secret_len()];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Parse a pairing secret from base36 encoding.
    pub fn from_base36(s: &str) -> Result<Self, PairingSecretError> {
        let bytes = decode_base36(s)?;
        Ok(Self { bytes })
    }

    /// Get the base36 encoding.
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
        let mut mac = HmacSha256::new_from_slice(&self.bytes).expect("HMAC can take any key size");
        mac.update(b"wispers-pairing-v1"); // salt
        mac.update(b"wispers-pairing-v1|mac"); // info
        let result = mac.finalize();
        result.into_bytes().into()
    }

    /// Compute HMAC for a pairing message payload.
    pub fn compute_mac(&self, payload: &[u8]) -> Vec<u8> {
        let key = self.derive_mac_key();
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take any key size");
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
    #[error("invalid length: expected 11 (interactive) or 14 (asynchronous) characters")]
    InvalidLength,
    #[error("invalid base36 character")]
    InvalidCharacter,
    #[error("pairing secret value out of range")]
    OutOfRange,
}

/// Encode a secret as lowercase base36, zero-padded to its profile's
/// `base36_len()`. The width that fits the bytes without loss is always
/// available because the byte length determines the profile.
fn encode_base36(bytes: &[u8]) -> String {
    let width = TtlProfile::from_secret_len(bytes.len())
        .expect("a secret always has a valid profile length")
        .base36_len();
    let s = BigUint::from_bytes_be(bytes).to_str_radix(36);
    debug_assert!(
        s.len() <= width,
        "{} bytes must fit in {width} base36 digits",
        bytes.len()
    );
    format!("{s:0>width$}")
}

/// Decode base36 characters to secret bytes.
fn decode_base36(s: &str) -> Result<Vec<u8>, PairingSecretError> {
    let secret_len = TtlProfile::from_base36_len(s.len())
        .ok_or(PairingSecretError::InvalidLength)?
        .secret_len();
    let n = BigUint::parse_bytes(s.as_bytes(), 36).ok_or(PairingSecretError::InvalidCharacter)?;
    let raw = n.to_bytes_be();
    // Reject values that exceed what `secret_len` bytes can hold: the base36
    // length can encode slightly more than the byte length holds (e.g. 11
    // digits reach 36^11−1 ≈ 1.3×10^17 but 7 bytes only 2^56−1 ≈ 7.2×10^16),
    // and that ~45% gap is where a mistyped code can land.
    if raw.len() > secret_len {
        return Err(PairingSecretError::OutOfRange);
    }
    // Left-pad to secret_len bytes (raw may be shorter for small values).
    let mut result = vec![0u8; secret_len];
    let offset = secret_len - raw.len();
    result[offset..].copy_from_slice(&raw);
    Ok(result)
}

//-- Pairing code (node_number + secret) -----------------------------------------------------------

/// A pairing code combining node number and secret for display/entry.
#[derive(Debug)]
pub struct PairingCode {
    pub node_number: i32,
    pub secret: PairingSecret,
}

impl PairingCode {
    /// Create a new pairing code.
    pub fn new(node_number: i32, secret: PairingSecret) -> Self {
        Self {
            node_number,
            secret,
        }
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
        let secret =
            PairingSecret::from_base36(parts[1]).map_err(PairingCodeError::InvalidSecret)?;
        Ok(Self {
            node_number,
            secret,
        })
    }
}

/// Error parsing a pairing code.
#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)] // "Invalid" prefix is meaningful here
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
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    impl TtlProfile {
        /// Every variant, for exhaustive tests. Kept honest by
        /// `ttl_profile_all_covers_every_variant`.
        const ALL: &'static [TtlProfile] = &[TtlProfile::Interactive, TtlProfile::Asynchronous];
    }

    /// Adding a `TtlProfile` variant makes this match non-exhaustive, which
    /// fails to compile — a nudge to add the variant to `TtlProfile::ALL` (so
    /// the entropy-floor check below covers it) and to re-check
    /// `PAIRING_RPC_DEADLINE`.
    #[test]
    fn ttl_profile_all_covers_every_variant() {
        for &p in TtlProfile::ALL {
            match p {
                TtlProfile::Interactive => {}
                TtlProfile::Asynchronous => {}
            }
        }
    }

    /// The new node's pairing-RPC deadline is a single constant
    /// (`PAIRING_RPC_DEADLINE`), calibrated to the weakest profile's
    /// entropy. So `Interactive` must stay the floor, and no profile may be
    /// weaker than it. This test fails if this precondition is ever violated.
    #[test]
    fn no_profile_is_weaker_than_interactive() {
        let floor = TtlProfile::Interactive.secret_len();
        assert_eq!(
            floor, 7,
            "PAIRING_RPC_DEADLINE (120s) is calibrated to a 7-byte/56-bit floor; \
             changing Interactive's entropy means re-deriving that deadline"
        );
        for &p in TtlProfile::ALL {
            assert!(
                p.secret_len() >= floor,
                "{p:?} has a {}-byte secret, weaker than Interactive's {}-byte floor; \
                 the fixed {}s pairing deadline would be unsafe for it",
                p.secret_len(),
                floor,
                PAIRING_RPC_DEADLINE.as_secs(),
            );
        }
    }

    #[test]
    fn test_base36_roundtrip() {
        let secret = PairingSecret::generate(TtlProfile::Interactive);
        let encoded = secret.to_base36();
        assert_eq!(encoded.len(), 11);
        let decoded = PairingSecret::from_base36(&encoded).unwrap();
        assert_eq!(secret.bytes, decoded.bytes);
    }

    /// The asynchronous profile round-trips through its 14-char encoding.
    #[test]
    fn test_base36_roundtrip_asynchronous() {
        let secret = PairingSecret::generate(TtlProfile::Asynchronous);
        let encoded = secret.to_base36();
        assert_eq!(encoded.len(), 14);
        let decoded = PairingSecret::from_base36(&encoded).unwrap();
        assert_eq!(secret.bytes, decoded.bytes);
    }

    /// Maximum-value secret (all 0xff) must round-trip — exercises the
    /// edge of the encodable range, for both profiles.
    #[test]
    fn test_base36_roundtrip_max_value() {
        for profile in [TtlProfile::Interactive, TtlProfile::Asynchronous] {
            let secret = PairingSecret {
                bytes: vec![0xff; profile.secret_len()],
            };
            let encoded = secret.to_base36();
            assert_eq!(encoded.len(), profile.base36_len());
            let decoded = PairingSecret::from_base36(&encoded).unwrap();
            assert_eq!(secret.bytes, decoded.bytes);
        }
    }

    /// All-zero secret must round-trip (tests the left-padding path).
    #[test]
    fn test_base36_roundtrip_zero_value() {
        let secret = PairingSecret {
            bytes: vec![0u8; 7],
        };
        let encoded = secret.to_base36();
        assert_eq!(encoded, "0".repeat(11));
        let decoded = PairingSecret::from_base36(&encoded).unwrap();
        assert_eq!(secret.bytes, decoded.bytes);
    }

    /// 11 valid base36 characters whose numeric value exceeds 2^56 must
    /// be rejected. This is the ~45% of 11-char base36 strings that
    /// represent values outside the 7-byte range.
    #[test]
    fn test_base36_rejects_out_of_range() {
        // "zzzzzzzzzzz" = 36^11 - 1, well above 2^56.
        let result = PairingSecret::from_base36("zzzzzzzzzzz");
        assert!(matches!(result, Err(PairingSecretError::OutOfRange)));
    }

    /// Wrong length is rejected with the specific error variant.
    #[test]
    fn test_base36_rejects_wrong_length() {
        // 10 chars (the old interactive length) must now be rejected.
        let result = PairingSecret::from_base36("0123456789");
        assert!(matches!(result, Err(PairingSecretError::InvalidLength)));
        // 12 chars: between the two valid lengths.
        let result = PairingSecret::from_base36("0123456789ab");
        assert!(matches!(result, Err(PairingSecretError::InvalidLength)));
        // 13 chars: just short of asynchronous.
        let result = PairingSecret::from_base36("0123456789abc");
        assert!(matches!(result, Err(PairingSecretError::InvalidLength)));
    }

    /// Non-base36 characters are rejected with the specific error variant.
    #[test]
    fn test_base36_rejects_invalid_characters() {
        // '!' is not a base36 digit.
        let result = PairingSecret::from_base36("abc!def12345");
        assert!(matches!(
            result,
            Err(PairingSecretError::InvalidLength | PairingSecretError::InvalidCharacter)
        ));
    }

    #[test]
    fn test_pairing_code_roundtrip() {
        for profile in [TtlProfile::Interactive, TtlProfile::Asynchronous] {
            let code = PairingCode::new(42, PairingSecret::generate(profile));
            let formatted = code.format();
            let parsed = PairingCode::parse(&formatted).unwrap();
            assert_eq!(code.node_number, parsed.node_number);
            assert_eq!(code.secret.bytes, parsed.secret.bytes);
            // The secret length (entropy tier) survives the round-trip.
            assert_eq!(parsed.secret.bytes.len(), profile.secret_len());
        }
    }

    #[test]
    fn test_mac_verification() {
        let secret = PairingSecret::generate(TtlProfile::Interactive);
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
    fn test_x25519_ephemeral_keys_differ() {
        let kp1 = X25519KeyPair::generate_ephemeral();
        let kp2 = X25519KeyPair::generate_ephemeral();
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_x25519_dh_shared_secret() {
        let alice = X25519KeyPair::generate_ephemeral();
        let bob = X25519KeyPair::generate_ephemeral();

        // Each performs DH with the other's public key
        let alice_shared = alice.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&alice.public_key());

        // They should arrive at the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }
}
