use crate::errors::{NodeStateError, WispersStatus};
use crate::state::{NodeStateManager, NodeStateStage, PendingNodeState, RegisteredNodeState};
use crate::storage::InMemoryStoreError;
use crate::storage::{ForeignNodeStateStore, InMemoryNodeStateStore, foreign::ForeignStoreError};
use crate::types::NodeRegistration;

pub enum ManagerImpl {
    InMemory(NodeStateManager<InMemoryNodeStateStore>),
    Foreign(NodeStateManager<ForeignNodeStateStore>),
}

pub enum PendingImpl {
    InMemory(PendingNodeState<InMemoryNodeStateStore>),
    Foreign(PendingNodeState<ForeignNodeStateStore>),
}

pub enum RegisteredImpl {
    InMemory(RegisteredNodeState<InMemoryNodeStateStore>),
    Foreign(RegisteredNodeState<ForeignNodeStateStore>),
}

pub struct WispersNodeStateManagerHandle(pub ManagerImpl);
pub struct WispersPendingNodeStateHandle(pub PendingImpl);
pub struct WispersRegisteredNodeStateHandle(pub RegisteredImpl);

pub enum NodeStateStageImpl {
    Pending(PendingImpl),
    Registered(RegisteredImpl),
}

type InMemoryStage = NodeStateStage<InMemoryNodeStateStore>;
type ForeignStage = NodeStateStage<ForeignNodeStateStore>;

impl NodeStateStageImpl {
    pub fn from_in_memory(stage: InMemoryStage) -> Self {
        match stage {
            NodeStateStage::Pending(pending) => {
                NodeStateStageImpl::Pending(PendingImpl::InMemory(pending))
            }
            NodeStateStage::Registered(registered) => {
                NodeStateStageImpl::Registered(RegisteredImpl::InMemory(registered))
            }
        }
    }

    pub fn from_foreign(stage: ForeignStage) -> Self {
        match stage {
            NodeStateStage::Pending(pending) => {
                NodeStateStageImpl::Pending(PendingImpl::Foreign(pending))
            }
            NodeStateStage::Registered(registered) => {
                NodeStateStageImpl::Registered(RegisteredImpl::Foreign(registered))
            }
        }
    }
}

impl From<NodeStateError<InMemoryStoreError>> for WispersStatus {
    fn from(value: NodeStateError<InMemoryStoreError>) -> Self {
        match value {
            NodeStateError::Store(_) => WispersStatus::StoreError,
            NodeStateError::AlreadyRegistered => WispersStatus::AlreadyRegistered,
            NodeStateError::NotRegistered => WispersStatus::NotRegistered,
        }
    }
}

impl From<NodeStateError<ForeignStoreError>> for WispersStatus {
    fn from(value: NodeStateError<ForeignStoreError>) -> Self {
        match value {
            NodeStateError::Store(ForeignStoreError::Status(status)) => status,
            NodeStateError::Store(ForeignStoreError::MissingCallback(_)) => {
                WispersStatus::MissingCallback
            }
            NodeStateError::Store(
                ForeignStoreError::CStringConversion
                | ForeignStoreError::RegistrationEncode
                | ForeignStoreError::RegistrationDecode,
            ) => WispersStatus::StoreError,
            NodeStateError::AlreadyRegistered => WispersStatus::AlreadyRegistered,
            NodeStateError::NotRegistered => WispersStatus::NotRegistered,
        }
    }
}

pub fn restore_or_init_internal(
    manager: &mut ManagerImpl,
    app_namespace: String,
    profile_namespace: Option<String>,
) -> Result<NodeStateStageImpl, WispersStatus> {
    match manager {
        ManagerImpl::InMemory(inner) => inner
            .restore_or_init_node_state(app_namespace, profile_namespace)
            .map(NodeStateStageImpl::from_in_memory)
            .map_err(Into::into),
        ManagerImpl::Foreign(inner) => inner
            .restore_or_init_node_state(app_namespace, profile_namespace)
            .map(NodeStateStageImpl::from_foreign)
            .map_err(Into::into),
    }
}

pub fn delete_registered_internal(registered: RegisteredImpl) -> Result<(), WispersStatus> {
    match registered {
        RegisteredImpl::InMemory(inner) => inner.delete().map_err(Into::into),
        RegisteredImpl::Foreign(inner) => inner.delete().map_err(Into::into),
    }
}

pub fn complete_registration_internal(
    pending: PendingImpl,
    registration: NodeRegistration,
) -> Result<RegisteredImpl, WispersStatus> {
    match pending {
        PendingImpl::InMemory(inner) => inner
            .complete_registration(registration)
            .map(RegisteredImpl::InMemory)
            .map_err(Into::into),
        PendingImpl::Foreign(inner) => inner
            .complete_registration(registration)
            .map(RegisteredImpl::Foreign)
            .map_err(Into::into),
    }
}

pub fn registration_url_internal(pending: &PendingImpl, base_url: &str) -> String {
    match pending {
        PendingImpl::InMemory(inner) => inner.registration_url(base_url),
        PendingImpl::Foreign(inner) => inner.registration_url(base_url),
    }
}
