import CWispersConnect

public enum NodeState: Int32, Sendable {
    case pending = 0
    case registered = 1
    case activated = 2
    case revoked = 3

    init(cValue: WispersNodeState) {
        self = NodeState(rawValue: Int32(cValue.rawValue)) ?? .pending
    }
}

public enum GroupState: Int32, Sendable {
    case alone = 0
    case bootstrap = 1
    case needActivation = 2
    case canEndorse = 3
    case allActivated = 4

    init(cValue: WispersGroupState) {
        self = GroupState(rawValue: Int32(cValue.rawValue)) ?? .alone
    }
}

/// TTL profile for activation codes (mirrors C enum `WispersTtlProfile`).
///
/// Selects the code's lifetime and entropy: `.interactive` is short-lived (for
/// live entry); `.asynchronous` is long-lived (for out-of-band delivery, e.g.
/// email).
public enum TtlProfile: Int32, Sendable {
    case interactive = 0
    case asynchronous = 1

    var cValue: WispersTtlProfile {
        switch self {
        case .interactive: return WISPERS_TTL_PROFILE_INTERACTIVE
        case .asynchronous: return WISPERS_TTL_PROFILE_ASYNCHRONOUS
        }
    }
}

public struct NodeInfo: Sendable, Identifiable {
    public var id: Int32 { nodeNumber }
    public let nodeNumber: Int32
    public let name: String
    public let metadata: String
    public let isSelf: Bool
    /// This node's lifecycle state observed from the local node. `.pending` never
    /// appears for a listed node.
    public let state: NodeState
    public let lastSeenAtMillis: Int64
    public let isOnline: Bool

    init(cNode: OpaquePointer) {
        self.nodeNumber = wispers_node_number(cNode)
        self.name = wispers_node_name(cNode).map { String(cString: $0) } ?? ""
        self.metadata = wispers_node_metadata(cNode).map { String(cString: $0) } ?? ""
        self.isSelf = wispers_node_is_self(cNode)
        self.state = NodeState(cValue: wispers_group_node_state(cNode))
        self.lastSeenAtMillis = wispers_node_last_seen_at_millis(cNode)
        self.isOnline = wispers_node_is_online(cNode)
    }

    /// Memberwise initializer — for tests and SwiftUI previews. The library
    /// itself builds `NodeInfo` from the C layer via the internal `init(cNode:)`.
    public init(
        nodeNumber: Int32,
        name: String,
        metadata: String,
        isSelf: Bool,
        state: NodeState,
        lastSeenAtMillis: Int64,
        isOnline: Bool
    ) {
        self.nodeNumber = nodeNumber
        self.name = name
        self.metadata = metadata
        self.isSelf = isSelf
        self.state = state
        self.lastSeenAtMillis = lastSeenAtMillis
        self.isOnline = isOnline
    }
}

public struct GroupInfo: Sendable {
    public let id: String
    public let name: String?
    public let createdAtMillis: Int64
    public let state: GroupState
    public let nodes: [NodeInfo]

    /// Memberwise initializer — for tests and SwiftUI previews. The library
    /// itself builds `GroupInfo` from the C layer (see `CallbackBridge`).
    public init(
        id: String,
        name: String?,
        createdAtMillis: Int64,
        state: GroupState,
        nodes: [NodeInfo]
    ) {
        self.id = id
        self.name = name
        self.createdAtMillis = createdAtMillis
        self.state = state
        self.nodes = nodes
    }
}

/// Snapshot of a serving session's hub connection and endorsing state.
public struct ServingStatus: Sendable {
    /// Whether the session currently holds a live hub stream. `false` while it
    /// is reconnecting after a hub disconnect.
    public let connected: Bool
    public let nodeNumber: Int32
    public let connectivityGroupId: String
    /// Number of activation codes awaiting use.
    public let codesOutstanding: Int
    /// Node numbers that have paired and await cosign.
    public let nodesAwaitingCosign: [Int32]
}

public struct RegistrationInfo: Sendable {
    public let connectivityGroupId: String
    public let nodeNumber: Int32
    public let authToken: String
    public let attestationJwt: String
}
