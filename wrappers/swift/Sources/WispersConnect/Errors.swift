import CWispersConnect

public enum WispersError: Error, Sendable {
    case nullPointer(String?)
    case invalidUtf8(String?)
    case storeError(String?)
    case alreadyRegistered(String?)
    case notRegistered(String?)
    case notFound(String?)
    case bufferTooSmall(String?)
    case missingCallback(String?)
    case invalidActivationCode(String?)
    case activationFailed(String?)
    case hubError(String?)
    case connectionFailed(String?)
    case timeout(String?)
    case invalidState(String?)
    case unauthenticated(String?)
    case peerRejected(String?)
    case peerUnavailable(String?)
    case unknown(code: Int32, detail: String?)

    static func fromStatus(_ status: WispersStatus, detail: String? = nil) -> WispersError {
        switch status.rawValue {
        case WISPERS_STATUS_NULL_POINTER.rawValue:          return .nullPointer(detail)
        case WISPERS_STATUS_INVALID_UTF8.rawValue:          return .invalidUtf8(detail)
        case WISPERS_STATUS_STORE_ERROR.rawValue:           return .storeError(detail)
        case WISPERS_STATUS_ALREADY_REGISTERED.rawValue:    return .alreadyRegistered(detail)
        case WISPERS_STATUS_NOT_REGISTERED.rawValue:        return .notRegistered(detail)
        case WISPERS_STATUS_NOT_FOUND.rawValue:             return .notFound(detail)
        case WISPERS_STATUS_BUFFER_TOO_SMALL.rawValue:      return .bufferTooSmall(detail)
        case WISPERS_STATUS_MISSING_CALLBACK.rawValue:      return .missingCallback(detail)
        case WISPERS_STATUS_INVALID_ACTIVATION_CODE.rawValue: return .invalidActivationCode(detail)
        case WISPERS_STATUS_ACTIVATION_FAILED.rawValue:     return .activationFailed(detail)
        case WISPERS_STATUS_HUB_ERROR.rawValue:             return .hubError(detail)
        case WISPERS_STATUS_CONNECTION_FAILED.rawValue:     return .connectionFailed(detail)
        case WISPERS_STATUS_TIMEOUT.rawValue:               return .timeout(detail)
        case WISPERS_STATUS_INVALID_STATE.rawValue:         return .invalidState(detail)
        case WISPERS_STATUS_UNAUTHENTICATED.rawValue:       return .unauthenticated(detail)
        case WISPERS_STATUS_PEER_REJECTED.rawValue:         return .peerRejected(detail)
        case WISPERS_STATUS_PEER_UNAVAILABLE.rawValue:      return .peerUnavailable(detail)
        default:                                            return .unknown(code: Int32(status.rawValue), detail: detail)
        }
    }

    static func check(_ status: WispersStatus) throws {
        if status.rawValue != WISPERS_STATUS_SUCCESS.rawValue {
            throw fromStatus(status)
        }
    }
}
