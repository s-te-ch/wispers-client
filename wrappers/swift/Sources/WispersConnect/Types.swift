import CWispersConnect

public enum NodeState: Int32, Sendable {
    case pending = 0
    case registered = 1
    case activated = 2

    init(cValue: WispersNodeState) {
        self = NodeState(rawValue: Int32(cValue.rawValue)) ?? .pending
    }
}

public enum ActivationStatus: Int32, Sendable {
    case unknown = 0
    case notActivated = 1
    case activated = 2

    init(cValue: Int32) {
        self = ActivationStatus(rawValue: cValue) ?? .unknown
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

public struct NodeInfo: Sendable, Identifiable {
    public var id: Int32 { nodeNumber }
    public let nodeNumber: Int32
    public let name: String
    public let metadata: String
    public let isSelf: Bool
    public let activationStatus: ActivationStatus
    public let lastSeenAtMillis: Int64
    public let isOnline: Bool

    init(cNode: OpaquePointer) {
        self.nodeNumber = wispers_node_number(cNode)
        self.name = wispers_node_name(cNode).map { String(cString: $0) } ?? ""
        self.metadata = wispers_node_metadata(cNode).map { String(cString: $0) } ?? ""
        self.isSelf = wispers_node_is_self(cNode)
        self.activationStatus = ActivationStatus(cValue: wispers_node_activation_status(cNode))
        self.lastSeenAtMillis = wispers_node_last_seen_at_millis(cNode)
        self.isOnline = wispers_node_is_online(cNode)
    }
}

public struct GroupInfo: Sendable {
    public let state: GroupState
    public let nodes: [NodeInfo]
}

public struct RegistrationInfo: Sendable {
    public let connectivityGroupId: String
    public let nodeNumber: Int32
    public let authToken: String
    public let attestationJwt: String
}
