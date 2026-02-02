//! File-based storage for node state.

use crate::storage::{NodeStateStore, StorageError};
use crate::types::{NodeRegistration, PersistedNodeState, RootKey, ROOT_KEY_LEN};
use std::fs;
use std::path::PathBuf;

/// File-based node state store.
///
/// Stores state in a directory:
/// ```text
/// dir/
///   root_key.bin
///   registration.json
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
            let json = fs::read_to_string(&registration_path)?;
            Some(serde_json::from_str::<NodeRegistration>(&json)?)
        } else {
            None
        };

        Ok(Some(PersistedNodeState {
            root_key: RootKey::from_bytes(key_array),
            registration,
        }))
    }

    fn save(&self, state: &PersistedNodeState) -> Result<(), StorageError> {
        fs::create_dir_all(&self.dir)?;

        // Save root key
        fs::write(self.root_key_path(), state.root_key.as_bytes())?;

        // Save registration if present
        let registration_path = self.registration_path();
        if let Some(ref registration) = state.registration {
            let json = serde_json::to_string_pretty(registration)?;
            fs::write(&registration_path, json)?;
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
