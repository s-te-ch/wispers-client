//! File-based storage for node state.

use crate::storage::{NodeStateStore, StorageError};
use crate::types::{AuthToken, ConnectivityGroupId, NodeRegistration, PersistedNodeState, ROOT_KEY_LEN};
use prost::Message;
use std::fs;
use std::path::PathBuf;

/// Proto-generated storage types.
mod proto {
    tonic::include_proto!("connect.storage");
}

/// File-based node state store.
///
/// Stores state in a directory:
/// ```text
/// dir/
///   root_key.bin
///   registration.pb
/// ```
///
/// The caller is responsible for constructing the path with any desired
/// namespacing (e.g., `base_dir.join(app).join(profile)`).
pub struct FileNodeStateStore {
    dir: PathBuf,
}

impl FileNodeStateStore {
    /// Create a new file-based store with the given directory.
    ///
    /// The directory should already include any namespacing (app, profile, etc.).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn root_key_path(&self) -> PathBuf {
        self.dir.join("root_key.bin")
    }

    fn registration_path(&self) -> PathBuf {
        self.dir.join("registration.pb")
    }

    /// Legacy JSON path for migration.
    fn legacy_registration_path(&self) -> PathBuf {
        self.dir.join("registration.json")
    }
}

impl NodeStateStore for FileNodeStateStore {
    fn load(&self) -> Result<Option<PersistedNodeState>, StorageError> {
        let root_key_path = self.root_key_path();

        // If root key doesn't exist, state doesn't exist
        if !root_key_path.exists() {
            return Ok(None);
        }

        // Load root key
        let root_key_bytes = fs::read(&root_key_path)?;
        if root_key_bytes.len() != ROOT_KEY_LEN {
            return Err(StorageError::InvalidRootKey);
        }
        let mut key_array = [0u8; ROOT_KEY_LEN];
        key_array.copy_from_slice(&root_key_bytes);

        // Load registration if present
        let registration_path = self.registration_path();
        let registration = if registration_path.exists() {
            let bytes = fs::read(&registration_path)?;
            match proto::NodeRegistration::decode(bytes.as_slice()) {
                Ok(proto_reg) => Some(NodeRegistration::new(
                    ConnectivityGroupId::new(proto_reg.connectivity_group_id),
                    proto_reg.node_number,
                    AuthToken::new(proto_reg.auth_token),
                    proto_reg.attestation_jwt,
                )),
                Err(_) => {
                    log::warn!("Registration decode failed, treating as empty");
                    None
                }
            }
        } else {
            // Migrate from legacy JSON format: delete it and let the node re-register.
            let legacy = self.legacy_registration_path();
            if legacy.exists() {
                log::warn!("Found legacy registration.json, removing (re-registration required)");
                let _ = fs::remove_file(&legacy);
            }
            None
        };

        Ok(Some(PersistedNodeState::from_stored(key_array, registration)))
    }

    fn save(&self, state: &PersistedNodeState) -> Result<(), StorageError> {
        fs::create_dir_all(&self.dir)?;

        // Save root key
        fs::write(self.root_key_path(), state.root_key_bytes())?;

        // Save registration if present
        let registration_path = self.registration_path();
        if let Some(registration) = state.registration() {
            let proto_reg = proto::NodeRegistration {
                connectivity_group_id: registration.connectivity_group_id.to_string(),
                node_number: registration.node_number,
                auth_token: registration.auth_token().map(|t| t.as_str().to_string()).unwrap_or_default(),
                attestation_jwt: registration.attestation_jwt.clone(),
            };
            fs::write(&registration_path, proto_reg.encode_to_vec())?;
        } else if registration_path.exists() {
            fs::remove_file(&registration_path)?;
        }

        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        if self.dir.exists() {
            fs::remove_dir_all(&self.dir)?;
        }
        Ok(())
    }
}
