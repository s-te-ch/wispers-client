//! Encryption for P2P UDP packets.
//!
//! Provides AES-256-GCM encryption with sequence number tracking for replay protection.
//! Derived from the desktop app's encryption.rs but adapted for bidirectional P2P connections.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

const PRK_INFO_CALLER_TO_ANSWERER: &[u8] = b"wispers-p2p-v1|c2a";
const PRK_INFO_ANSWERER_TO_CALLER: &[u8] = b"wispers-p2p-v1|a2c";
const NONCE_PREFIX_INFO: &[u8] = b"wispers-p2p-v1|np";
const AAD_PREFIX: &[u8; 16] = b"wispers-p2p-v1|a";

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("HKDF expand failed")]
    Hkdf,

    #[error("encryption failed")]
    Encrypt,

    #[error("decryption failed")]
    Decrypt,

    #[error("packet too short")]
    PacketTooShort,
}

/// Encrypts outgoing packets with sequence number tracking.
pub struct Encrypter {
    aead: Aes256Gcm,
    nonce_prefix: [u8; 4],
    seqno: AtomicU64,
}

impl Encrypter {
    fn new(aead_key: [u8; 32], nonce_prefix: [u8; 4]) -> Self {
        let aead = Aes256Gcm::new_from_slice(&aead_key).expect("32 bytes is valid AES-256 key");
        Self {
            aead,
            nonce_prefix,
            seqno: AtomicU64::new(0),
        }
    }

    /// Encrypt a packet. Returns the ciphertext with prepended sequence number.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let seqno = self.seqno.fetch_add(1, Ordering::Relaxed);
        let nonce_bytes = build_nonce(self.nonce_prefix, seqno);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let aad = build_aad(seqno);

        let ciphertext = self
            .aead
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| EncryptionError::Encrypt)?;

        // Prepend seqno to ciphertext so receiver knows which nonce to use
        let mut packet = Vec::with_capacity(8 + ciphertext.len());
        packet.extend_from_slice(&seqno.to_le_bytes());
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }
}

/// Decrypts incoming packets.
///
/// Does not enforce sequence ordering - packets can arrive out of order or be lost.
/// The sequence number in each packet is used only for nonce derivation.
pub struct Decrypter {
    aead: Aes256Gcm,
    nonce_prefix: [u8; 4],
}

impl Decrypter {
    fn new(aead_key: [u8; 32], nonce_prefix: [u8; 4]) -> Self {
        let aead = Aes256Gcm::new_from_slice(&aead_key).expect("32 bytes is valid AES-256 key");
        Self { aead, nonce_prefix }
    }

    /// Decrypt a packet using the sequence number embedded in it.
    pub fn decrypt(&self, packet: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if packet.len() < 8 {
            return Err(EncryptionError::PacketTooShort);
        }

        let seqno = u64::from_le_bytes(packet[..8].try_into().unwrap());
        let ciphertext = &packet[8..];

        let nonce_bytes = build_nonce(self.nonce_prefix, seqno);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let aad = build_aad(seqno);

        let plaintext = self
            .aead
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| EncryptionError::Decrypt)?;

        Ok(plaintext)
    }
}

/// Encryption context for a P2P connection.
///
/// Handles bidirectional encryption with direction-specific keys.
pub struct P2pCipher {
    encrypter: Encrypter,
    decrypter: Decrypter,
}

impl P2pCipher {
    /// Create cipher for the caller side of a connection.
    pub fn new_caller(shared_secret: &[u8; 32], connection_id: i64) -> Result<Self, EncryptionError> {
        let connection_id_bytes = connection_id.to_le_bytes();

        // Caller encrypts with c2a key, decrypts with a2c key
        let (send_key, send_nonce_prefix) =
            derive_direction_keys(shared_secret, &connection_id_bytes, PRK_INFO_CALLER_TO_ANSWERER)?;
        let (recv_key, recv_nonce_prefix) =
            derive_direction_keys(shared_secret, &connection_id_bytes, PRK_INFO_ANSWERER_TO_CALLER)?;

        Ok(Self {
            encrypter: Encrypter::new(send_key, send_nonce_prefix),
            decrypter: Decrypter::new(recv_key, recv_nonce_prefix),
        })
    }

    /// Create cipher for the answerer side of a connection.
    pub fn new_answerer(shared_secret: &[u8; 32], connection_id: i64) -> Result<Self, EncryptionError> {
        let connection_id_bytes = connection_id.to_le_bytes();

        // Answerer encrypts with a2c key, decrypts with c2a key
        let (send_key, send_nonce_prefix) =
            derive_direction_keys(shared_secret, &connection_id_bytes, PRK_INFO_ANSWERER_TO_CALLER)?;
        let (recv_key, recv_nonce_prefix) =
            derive_direction_keys(shared_secret, &connection_id_bytes, PRK_INFO_CALLER_TO_ANSWERER)?;

        Ok(Self {
            encrypter: Encrypter::new(send_key, send_nonce_prefix),
            decrypter: Decrypter::new(recv_key, recv_nonce_prefix),
        })
    }

    /// Encrypt data for sending.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        self.encrypter.encrypt(plaintext)
    }

    /// Decrypt received data.
    pub fn decrypt(&self, packet: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        self.decrypter.decrypt(packet)
    }
}

/// Derive direction-specific AEAD key and nonce prefix.
fn derive_direction_keys(
    shared_secret: &[u8; 32],
    connection_id: &[u8; 8],
    direction_info: &[u8],
) -> Result<([u8; 32], [u8; 4]), EncryptionError> {
    // Use connection_id as salt
    let hkdf = Hkdf::<Sha256>::new(Some(connection_id), shared_secret);

    let mut aead_key = [0u8; 32];
    hkdf.expand(direction_info, &mut aead_key)
        .map_err(|_| EncryptionError::Hkdf)?;

    // Derive nonce prefix with direction-specific info
    let mut nonce_info = Vec::with_capacity(NONCE_PREFIX_INFO.len() + direction_info.len());
    nonce_info.extend_from_slice(NONCE_PREFIX_INFO);
    nonce_info.extend_from_slice(direction_info);

    let mut nonce_prefix = [0u8; 4];
    hkdf.expand(&nonce_info, &mut nonce_prefix)
        .map_err(|_| EncryptionError::Hkdf)?;

    Ok((aead_key, nonce_prefix))
}

/// Build 12-byte nonce from 4-byte prefix and 8-byte sequence number.
fn build_nonce(prefix: [u8; 4], seqno: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&seqno.to_le_bytes());
    nonce
}

/// Build additional authenticated data from sequence number.
fn build_aad(seqno: u64) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[..16].copy_from_slice(AAD_PREFIX);
    aad[16..].copy_from_slice(&seqno.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_caller_to_answerer() {
        let shared_secret = [0x42u8; 32];
        let connection_id = 12345i64;

        let caller = P2pCipher::new_caller(&shared_secret, connection_id).unwrap();
        let answerer = P2pCipher::new_answerer(&shared_secret, connection_id).unwrap();

        // Caller sends to answerer
        let plaintext = b"hello from caller";
        let encrypted = caller.encrypt(plaintext).unwrap();
        let decrypted = answerer.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_answerer_to_caller() {
        let shared_secret = [0x42u8; 32];
        let connection_id = 12345i64;

        let caller = P2pCipher::new_caller(&shared_secret, connection_id).unwrap();
        let answerer = P2pCipher::new_answerer(&shared_secret, connection_id).unwrap();

        // Answerer sends to caller
        let plaintext = b"hello from answerer";
        let encrypted = answerer.encrypt(plaintext).unwrap();
        let decrypted = caller.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn bidirectional_conversation() {
        let shared_secret = [0x42u8; 32];
        let connection_id = 99i64;

        let caller = P2pCipher::new_caller(&shared_secret, connection_id).unwrap();
        let answerer = P2pCipher::new_answerer(&shared_secret, connection_id).unwrap();

        // Multiple messages in both directions
        for i in 0..5 {
            let msg = format!("caller message {}", i);
            let enc = caller.encrypt(msg.as_bytes()).unwrap();
            let dec = answerer.decrypt(&enc).unwrap();
            assert_eq!(dec, msg.as_bytes());

            let msg = format!("answerer message {}", i);
            let enc = answerer.encrypt(msg.as_bytes()).unwrap();
            let dec = caller.decrypt(&enc).unwrap();
            assert_eq!(dec, msg.as_bytes());
        }
    }

    #[test]
    fn accepts_out_of_order() {
        let shared_secret = [0x42u8; 32];
        let connection_id = 1i64;

        let caller = P2pCipher::new_caller(&shared_secret, connection_id).unwrap();
        let answerer = P2pCipher::new_answerer(&shared_secret, connection_id).unwrap();

        let enc1 = caller.encrypt(b"first").unwrap();
        let enc2 = caller.encrypt(b"second").unwrap();
        let enc3 = caller.encrypt(b"third").unwrap();

        // Decrypt out of order - all should work
        let dec2 = answerer.decrypt(&enc2).unwrap();
        assert_eq!(dec2, b"second");

        let dec3 = answerer.decrypt(&enc3).unwrap();
        assert_eq!(dec3, b"third");

        let dec1 = answerer.decrypt(&enc1).unwrap();
        assert_eq!(dec1, b"first");
    }

    #[test]
    fn handles_packet_loss() {
        let shared_secret = [0x42u8; 32];
        let connection_id = 1i64;

        let caller = P2pCipher::new_caller(&shared_secret, connection_id).unwrap();
        let answerer = P2pCipher::new_answerer(&shared_secret, connection_id).unwrap();

        let _enc1 = caller.encrypt(b"first").unwrap(); // "lost"
        let enc2 = caller.encrypt(b"second").unwrap();
        let _enc3 = caller.encrypt(b"third").unwrap(); // "lost"
        let enc4 = caller.encrypt(b"fourth").unwrap();

        // Only receive packets 2 and 4
        let dec2 = answerer.decrypt(&enc2).unwrap();
        assert_eq!(dec2, b"second");

        let dec4 = answerer.decrypt(&enc4).unwrap();
        assert_eq!(dec4, b"fourth");
    }

    #[test]
    fn different_connections_have_different_keys() {
        let shared_secret = [0x42u8; 32];

        let cipher1 = P2pCipher::new_caller(&shared_secret, 1).unwrap();
        let cipher2 = P2pCipher::new_answerer(&shared_secret, 2).unwrap(); // Different connection_id

        let encrypted = cipher1.encrypt(b"test").unwrap();

        // cipher2 can't decrypt because it has different keys (different connection_id)
        let result = cipher2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let shared_secret = [0x42u8; 32];
        let connection_id = 1i64;

        let caller = P2pCipher::new_caller(&shared_secret, connection_id).unwrap();
        let answerer = P2pCipher::new_answerer(&shared_secret, connection_id).unwrap();

        let mut encrypted = caller.encrypt(b"secret message").unwrap();

        // Tamper with ciphertext (after the 8-byte seqno)
        encrypted[10] ^= 0xFF;

        let result = answerer.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_shared_secret_fails() {
        let connection_id = 1i64;

        let caller = P2pCipher::new_caller(&[0x42u8; 32], connection_id).unwrap();
        let answerer = P2pCipher::new_answerer(&[0x99u8; 32], connection_id).unwrap(); // Different secret

        let encrypted = caller.encrypt(b"secret message").unwrap();

        let result = answerer.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn packet_too_short_fails() {
        let shared_secret = [0x42u8; 32];
        let answerer = P2pCipher::new_answerer(&shared_secret, 1).unwrap();

        // Packet shorter than 8-byte seqno header
        let result = answerer.decrypt(&[0u8; 7]);
        assert!(matches!(result, Err(EncryptionError::PacketTooShort)));
    }
}
