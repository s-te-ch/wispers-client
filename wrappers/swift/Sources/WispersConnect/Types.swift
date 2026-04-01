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

public struct NodeInfo: Sendable {
    public let nodeNumber: Int32
    public let name: String
    public let metadata: String
    public let isSelf: Bool
    public let activationStatus: ActivationStatus
    public let lastSeenAtMillis: Int64
    public let isOnline: Bool

    init(cNode: WispersNode) {
        self.nodeNumber = cNode.node_number
        self.name = cNode.name.map { String(cString: $0) } ?? ""
        self.metadata = cNode.metadata.map { String(cString: $0) } ?? ""
        self.isSelf = cNode.is_self
        self.activationStatus = ActivationStatus(cValue: cNode.activation_status)
        self.lastSeenAtMillis = cNode.last_seen_at_millis
        self.isOnline = cNode.is_online
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
