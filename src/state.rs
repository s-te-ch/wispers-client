use crate::errors::NodeStateError;
use crate::storage::{NodeStateStore, SharedStore};
use crate::types::{AppNamespace, NodeRegistration, NodeState, ProfileNamespace};
use std::sync::Arc;
use urlencoding::encode;

/// High-level manager that drives state initialization and persistence.
#[derive(Clone)]
pub struct NodeStateManager<S: NodeStateStore> {
    store: SharedStore<S>,
}

impl<S: NodeStateStore> NodeStateManager<S> {
    pub fn new(store: S) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    pub fn restore_or_init_node_state(
        &self,
        app_namespace: impl Into<AppNamespace>,
        profile_namespace: Option<impl Into<ProfileNamespace>>,
    ) -> Result<NodeStateStage<S>, NodeStateError<S::Error>> {
        let app_namespace = app_namespace.into();
        let profile_namespace = profile_namespace
            .map(Into::into)
            .unwrap_or_else(ProfileNamespace::default);

        match self
            .store
            .load(&app_namespace, &profile_namespace)
            .map_err(NodeStateError::store)?
        {
            Some(state) => NodeStateStage::from_state(state, self.store.clone()),
            None => {
                let state = NodeState::initialize_with_namespaces(
                    app_namespace.clone(),
                    profile_namespace.clone(),
                );
                self.store.save(&state).map_err(NodeStateError::store)?;
                Ok(NodeStateStage::Pending(PendingNodeState::new(
                    state,
                    self.store.clone(),
                )))
            }
        }
    }
}

/// State machine representing whether a node still needs registration.
pub enum NodeStateStage<S: NodeStateStore> {
    Pending(PendingNodeState<S>),
    Registered(RegisteredNodeState<S>),
}

impl<S: NodeStateStore> NodeStateStage<S> {
    fn from_state(
        state: NodeState,
        store: SharedStore<S>,
    ) -> Result<Self, NodeStateError<S::Error>> {
        if state.is_registered() {
            Ok(Self::Registered(RegisteredNodeState::new(state, store)?))
        } else {
            Ok(Self::Pending(PendingNodeState::new(state, store)))
        }
    }

    pub fn into_pending(self) -> Option<PendingNodeState<S>> {
        if let NodeStateStage::Pending(state) = self {
            Some(state)
        } else {
            None
        }
    }

    pub fn into_registered(self) -> Option<RegisteredNodeState<S>> {
        if let NodeStateStage::Registered(state) = self {
            Some(state)
        } else {
            None
        }
    }
}

/// Pending node state that has not completed remote registration.
pub struct PendingNodeState<S: NodeStateStore> {
    state: NodeState,
    store: SharedStore<S>,
}

impl<S: NodeStateStore> PendingNodeState<S> {
    pub(crate) fn new(state: NodeState, store: SharedStore<S>) -> Self {
        Self { state, store }
    }

    pub fn app_namespace(&self) -> &AppNamespace {
        &self.state.app_namespace
    }

    pub fn profile_namespace(&self) -> &ProfileNamespace {
        &self.state.profile_namespace
    }

    pub fn is_registered(&self) -> bool {
        self.state.is_registered()
    }

    pub fn registration_url(&self, base_url: &str) -> String {
        let separator = if base_url.contains('?') { '&' } else { '?' };
        format!(
            "{base_url}{separator}app_namespace={}&profile_namespace={}",
            encode(self.app_namespace().as_ref()),
            encode(self.profile_namespace().as_ref())
        )
    }

    pub fn complete_registration(
        mut self,
        registration: NodeRegistration,
    ) -> Result<RegisteredNodeState<S>, NodeStateError<S::Error>> {
        if self.state.is_registered() {
            return Err(NodeStateError::AlreadyRegistered);
        }

        self.state.set_registration(registration);
        self.store
            .save(&self.state)
            .map_err(NodeStateError::store)?;
        RegisteredNodeState::new(self.state, self.store)
    }

    #[cfg(test)]
    pub(crate) fn root_key_bytes(&self) -> &[u8; crate::types::ROOT_KEY_LEN] {
        self.state.root_key.as_bytes()
    }
}

/// Registered node state ready for node runtime initialization.
pub struct RegisteredNodeState<S: NodeStateStore> {
    state: NodeState,
    store: SharedStore<S>,
}

impl<S: NodeStateStore> RegisteredNodeState<S> {
    pub(crate) fn new(
        state: NodeState,
        store: SharedStore<S>,
    ) -> Result<Self, NodeStateError<S::Error>> {
        if state.registration.is_none() {
            return Err(NodeStateError::NotRegistered);
        }

        Ok(Self { state, store })
    }

    pub fn app_namespace(&self) -> &AppNamespace {
        &self.state.app_namespace
    }

    pub fn profile_namespace(&self) -> &ProfileNamespace {
        &self.state.profile_namespace
    }

    pub fn registration(&self) -> &NodeRegistration {
        self.state
            .registration
            .as_ref()
            .expect("registration must be present")
    }

    pub fn delete(self) -> Result<(), NodeStateError<S::Error>> {
        let app = self.state.app_namespace.clone();
        let profile = self.state.profile_namespace.clone();
        self.store
            .delete(&app, &profile)
            .map_err(NodeStateError::store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryNodeStateStore;
    use crate::types::DEFAULT_PROFILE_NAMESPACE;

    #[test]
    fn manager_initializes_and_reuses_state() {
        let manager = NodeStateManager::new(InMemoryNodeStateStore::new());
        let first_stage = manager
            .restore_or_init_node_state("app.example", None::<String>)
            .unwrap();
        let pending = first_stage
            .into_pending()
            .expect("initial state should be pending");
        assert_eq!(pending.app_namespace().as_ref(), "app.example");
        assert_eq!(
            pending.profile_namespace().as_ref(),
            DEFAULT_PROFILE_NAMESPACE
        );
        let first_key = *pending.root_key_bytes();

        let second_stage = manager
            .restore_or_init_node_state("app.example", None::<String>)
            .unwrap();
        let pending_second = second_stage
            .into_pending()
            .expect("state remains pending until registration");
        assert_eq!(pending_second.root_key_bytes(), &first_key);
    }

    #[test]
    fn completing_registration_persists_and_transitions() {
        let manager = NodeStateManager::new(InMemoryNodeStateStore::new());
        let stage = manager
            .restore_or_init_node_state("app.example", None::<String>)
            .unwrap();
        let pending = stage
            .into_pending()
            .expect("expected pending state prior to registration");
        let registration = crate::types::registration_fixture();

        let registered = pending.complete_registration(registration.clone()).unwrap();
        assert_eq!(registered.registration(), &registration);

        let loaded_stage = manager
            .restore_or_init_node_state("app.example", None::<String>)
            .unwrap();
        assert!(matches!(loaded_stage, NodeStateStage::Registered(_)));
    }
}
