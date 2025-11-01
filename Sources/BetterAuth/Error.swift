import Foundation

// swiftlint:disable file_length

// MARK: - Better Auth Error

public struct BetterAuthError: Error, Codable, @unchecked Sendable {
    public let code: String
    public let message: String
    public let context: [String: AnyCodable]?

    private init(code: String, message: String, context: [String: AnyCodable]? = nil) {
        self.code = code
        self.message = message
        self.context = context
    }

    // MARK: - Validation Errors

    /// Message structure is invalid or malformed (BA101)
    public static func invalidMessage(
        field: String? = nil,
        details: String? = nil
    ) -> BetterAuthError {
        var message = "Message structure is invalid or malformed"
        if let field {
            message = "Message structure is invalid: \(field)"
            if let details {
                message += " (\(details))"
            }
        }

        var context: [String: AnyCodable]?
        if field != nil || details != nil {
            context = [:]
            if let field { context?["field"] = AnyCodable(field) }
            if let details { context?["details"] = AnyCodable(details) }
        }

        return BetterAuthError(code: "BA101", message: message, context: context)
    }

    /// Identity verification failed (BA102)
    public static func invalidIdentity(
        provided: String? = nil,
        details: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if provided != nil || details != nil {
            context = [:]
            if let provided { context?["provided"] = AnyCodable(provided) }
            if let details { context?["details"] = AnyCodable(details) }
        }

        return BetterAuthError(
            code: "BA102",
            message: "Identity verification failed",
            context: context
        )
    }

    /// Device hash does not match hash(publicKey || rotationHash) (BA103)
    public static func invalidDevice(
        provided: String? = nil,
        calculated: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if provided != nil || calculated != nil {
            context = [:]
            if let provided { context?["provided"] = AnyCodable(provided) }
            if let calculated { context?["calculated"] = AnyCodable(calculated) }
        }

        return BetterAuthError(
            code: "BA103",
            message: "Device hash does not match hash(publicKey || rotationHash)",
            context: context
        )
    }

    /// Hash validation failed (BA104)
    public static func invalidHash(
        expected: String? = nil,
        actual: String? = nil,
        hashType: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if expected != nil || actual != nil || hashType != nil {
            context = [:]
            if let expected { context?["expected"] = AnyCodable(expected) }
            if let actual { context?["actual"] = AnyCodable(actual) }
            if let hashType { context?["hashType"] = AnyCodable(hashType) }
        }

        return BetterAuthError(code: "BA104", message: "Hash validation failed", context: context)
    }

    // MARK: - Cryptographic Errors

    /// Signature verification failed (BA201)
    public static func signatureVerificationFailed(
        publicKey: String? = nil,
        signedData: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if publicKey != nil || signedData != nil {
            context = [:]
            if let publicKey { context?["publicKey"] = AnyCodable(publicKey) }
            if let signedData { context?["signedData"] = AnyCodable(signedData) }
        }

        return BetterAuthError(
            code: "BA201",
            message: "Signature verification failed",
            context: context
        )
    }

    /// Response nonce does not match request nonce (BA203)
    public static func incorrectNonce(
        expected: String? = nil,
        actual: String? = nil
    ) -> BetterAuthError {
        let truncate: (String) -> String = { str in
            str.count > 16 ? "\(str.prefix(16))..." : str
        }

        var context: [String: AnyCodable]?
        if expected != nil || actual != nil {
            context = [:]
            if let expected { context?["expected"] = AnyCodable(truncate(expected)) }
            if let actual { context?["actual"] = AnyCodable(truncate(actual)) }
        }

        return BetterAuthError(
            code: "BA203",
            message: "Response nonce does not match request nonce",
            context: context
        )
    }

    /// Authentication challenge has expired (BA204)
    public static func expiredNonce(
        nonceTimestamp: String? = nil,
        currentTime: String? = nil,
        expirationWindow: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if nonceTimestamp != nil || currentTime != nil || expirationWindow != nil {
            context = [:]
            if let nonceTimestamp {
                context?["nonceTimestamp"] = AnyCodable(nonceTimestamp)
            }
            if let currentTime { context?["currentTime"] = AnyCodable(currentTime) }
            if let expirationWindow {
                context?["expirationWindow"] = AnyCodable(expirationWindow)
            }
        }

        return BetterAuthError(
            code: "BA204",
            message: "Authentication challenge has expired",
            context: context
        )
    }

    /// Nonce has already been used (replay attack detected) (BA205)
    public static func nonceReplay(
        nonce: String? = nil,
        previousUsageTimestamp: String? = nil
    ) -> BetterAuthError {
        let truncate: (String) -> String = { str in
            str.count > 16 ? "\(str.prefix(16))..." : str
        }

        var context: [String: AnyCodable]?
        if nonce != nil || previousUsageTimestamp != nil {
            context = [:]
            if let nonce { context?["nonce"] = AnyCodable(truncate(nonce)) }
            if let previousUsageTimestamp {
                context?["previousUsageTimestamp"] = AnyCodable(previousUsageTimestamp)
            }
        }

        return BetterAuthError(
            code: "BA205",
            message: "Nonce has already been used (replay attack detected)",
            context: context
        )
    }

    // MARK: - Authentication/Authorization Errors

    /// Link container identity does not match request identity (BA302)
    public static func mismatchedIdentities(
        linkContainerIdentity: String? = nil,
        requestIdentity: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if linkContainerIdentity != nil || requestIdentity != nil {
            context = [:]
            if let linkContainerIdentity {
                context?["linkContainerIdentity"] = AnyCodable(linkContainerIdentity)
            }
            if let requestIdentity { context?["requestIdentity"] = AnyCodable(requestIdentity) }
        }

        return BetterAuthError(
            code: "BA302",
            message: "Link container identity does not match request identity",
            context: context
        )
    }

    /// Insufficient permissions for requested operation (BA303)
    public static func permissionDenied(
        requiredPermissions: [String]? = nil,
        actualPermissions: [String]? = nil,
        operation: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if requiredPermissions != nil || actualPermissions != nil || operation != nil {
            context = [:]
            if let requiredPermissions { context?["requiredPermissions"] = AnyCodable(requiredPermissions) }
            if let actualPermissions { context?["actualPermissions"] = AnyCodable(actualPermissions) }
            if let operation { context?["operation"] = AnyCodable(operation) }
        }

        return BetterAuthError(
            code: "BA303",
            message: "Insufficient permissions for requested operation",
            context: context
        )
    }

    // MARK: - Token Errors

    /// Token has expired (BA401)
    public static func expiredToken(
        expiryTime: String? = nil,
        currentTime: String? = nil,
        tokenType: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if expiryTime != nil || currentTime != nil || tokenType != nil {
            context = [:]
            if let expiryTime { context?["expiryTime"] = AnyCodable(expiryTime) }
            if let currentTime { context?["currentTime"] = AnyCodable(currentTime) }
            if let tokenType { context?["tokenType"] = AnyCodable(tokenType) }
        }

        return BetterAuthError(code: "BA401", message: "Token has expired", context: context)
    }

    /// Token structure or format is invalid (BA402)
    public static func invalidToken(details: String? = nil) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if let details {
            context = ["details": AnyCodable(details)]
        }

        return BetterAuthError(code: "BA402", message: "Token structure or format is invalid", context: context)
    }

    /// Token issued_at timestamp is in the future (BA403)
    public static func futureToken(
        issuedAt: String? = nil,
        currentTime: String? = nil,
        timeDifference: Double? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if issuedAt != nil || currentTime != nil || timeDifference != nil {
            context = [:]
            if let issuedAt { context?["issuedAt"] = AnyCodable(issuedAt) }
            if let currentTime { context?["currentTime"] = AnyCodable(currentTime) }
            if let timeDifference { context?["timeDifference"] = AnyCodable(timeDifference) }
        }

        return BetterAuthError(code: "BA403", message: "Token issued_at timestamp is in the future", context: context)
    }

    // MARK: - Temporal Errors

    /// Request timestamp is too old (BA501)
    public static func staleRequest(
        requestTimestamp: String? = nil,
        currentTime: String? = nil,
        maximumAge: Int? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if requestTimestamp != nil || currentTime != nil || maximumAge != nil {
            context = [:]
            if let requestTimestamp { context?["requestTimestamp"] = AnyCodable(requestTimestamp) }
            if let currentTime { context?["currentTime"] = AnyCodable(currentTime) }
            if let maximumAge { context?["maximumAge"] = AnyCodable(maximumAge) }
        }

        return BetterAuthError(code: "BA501", message: "Request timestamp is too old", context: context)
    }

    /// Request timestamp is in the future (BA502)
    public static func futureRequest(
        requestTimestamp: String? = nil,
        currentTime: String? = nil,
        timeDifference: Double? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if requestTimestamp != nil || currentTime != nil || timeDifference != nil {
            context = [:]
            if let requestTimestamp { context?["requestTimestamp"] = AnyCodable(requestTimestamp) }
            if let currentTime { context?["currentTime"] = AnyCodable(currentTime) }
            if let timeDifference { context?["timeDifference"] = AnyCodable(timeDifference) }
        }

        return BetterAuthError(code: "BA502", message: "Request timestamp is in the future", context: context)
    }

    /// Client and server clock difference exceeds tolerance (BA503)
    public static func clockSkew(
        clientTime: String? = nil,
        serverTime: String? = nil,
        timeDifference: Double? = nil,
        maxTolerance: Double? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if clientTime != nil || serverTime != nil || timeDifference != nil || maxTolerance != nil {
            context = [:]
            if let clientTime { context?["clientTime"] = AnyCodable(clientTime) }
            if let serverTime { context?["serverTime"] = AnyCodable(serverTime) }
            if let timeDifference { context?["timeDifference"] = AnyCodable(timeDifference) }
            if let maxTolerance { context?["maxTolerance"] = AnyCodable(maxTolerance) }
        }

        return BetterAuthError(
            code: "BA503",
            message: "Client and server clock difference exceeds tolerance",
            context: context
        )
    }

    // MARK: - Storage Errors

    /// Resource not found (BA601)
    public static func notFound(resourceType: String? = nil, resourceIdentifier: String? = nil) -> BetterAuthError {
        var message = "Resource not found"
        if let resourceType {
            message = "Resource not found: \(resourceType)"
        }

        var context: [String: AnyCodable]?
        if resourceType != nil || resourceIdentifier != nil {
            context = [:]
            if let resourceType { context?["resourceType"] = AnyCodable(resourceType) }
            if let resourceIdentifier { context?["resourceIdentifier"] = AnyCodable(resourceIdentifier) }
        }

        return BetterAuthError(code: "BA601", message: message, context: context)
    }

    /// Resource already exists (BA602)
    public static func alreadyExists(
        resourceType: String? = nil,
        resourceIdentifier: String? = nil
    ) -> BetterAuthError {
        var message = "Resource already exists"
        if let resourceType {
            message = "Resource already exists: \(resourceType)"
        }

        var context: [String: AnyCodable]?
        if resourceType != nil || resourceIdentifier != nil {
            context = [:]
            if let resourceType { context?["resourceType"] = AnyCodable(resourceType) }
            if let resourceIdentifier { context?["resourceIdentifier"] = AnyCodable(resourceIdentifier) }
        }

        return BetterAuthError(code: "BA602", message: message, context: context)
    }

    /// Storage backend is unavailable (BA603)
    public static func storageUnavailable(
        backendType: String? = nil,
        connectionDetails: String? = nil,
        backendError: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if backendType != nil || connectionDetails != nil || backendError != nil {
            context = [:]
            if let backendType { context?["backendType"] = AnyCodable(backendType) }
            if let connectionDetails { context?["connectionDetails"] = AnyCodable(connectionDetails) }
            if let backendError { context?["backendError"] = AnyCodable(backendError) }
        }

        return BetterAuthError(code: "BA603", message: "Storage backend is unavailable", context: context)
    }

    /// Stored data is corrupted or invalid (BA604)
    public static func storageCorruption(
        resourceType: String? = nil,
        resourceIdentifier: String? = nil,
        corruptionDetails: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if resourceType != nil || resourceIdentifier != nil || corruptionDetails != nil {
            context = [:]
            if let resourceType { context?["resourceType"] = AnyCodable(resourceType) }
            if let resourceIdentifier { context?["resourceIdentifier"] = AnyCodable(resourceIdentifier) }
            if let corruptionDetails { context?["corruptionDetails"] = AnyCodable(corruptionDetails) }
        }

        return BetterAuthError(code: "BA604", message: "Stored data is corrupted or invalid", context: context)
    }

    // MARK: - Encoding Errors

    /// Failed to serialize message (BA701)
    public static func serializationError(
        messageType: String? = nil,
        format: String? = nil,
        details: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if messageType != nil || format != nil || details != nil {
            context = [:]
            if let messageType { context?["messageType"] = AnyCodable(messageType) }
            if let format { context?["format"] = AnyCodable(format) }
            if let details { context?["details"] = AnyCodable(details) }
        }

        return BetterAuthError(code: "BA701", message: "Failed to serialize message", context: context)
    }

    /// Failed to deserialize message (BA702)
    public static func deserializationError(
        messageType: String? = nil,
        rawData: String? = nil,
        details: String? = nil
    ) -> BetterAuthError {
        let truncateData: (String) -> String = { str in
            str.count > 100 ? "\(str.prefix(100))..." : str
        }

        var context: [String: AnyCodable]?
        if messageType != nil || rawData != nil || details != nil {
            context = [:]
            if let messageType { context?["messageType"] = AnyCodable(messageType) }
            if let rawData { context?["rawData"] = AnyCodable(truncateData(rawData)) }
            if let details { context?["details"] = AnyCodable(details) }
        }

        return BetterAuthError(code: "BA702", message: "Failed to deserialize message", context: context)
    }

    /// Failed to compress or decompress data (BA703)
    public static func compressionError(
        operation: String? = nil,
        dataSize: Int? = nil,
        details: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if operation != nil || dataSize != nil || details != nil {
            context = [:]
            if let operation { context?["operation"] = AnyCodable(operation) }
            if let dataSize { context?["dataSize"] = AnyCodable(dataSize) }
            if let details { context?["details"] = AnyCodable(details) }
        }

        return BetterAuthError(code: "BA703", message: "Failed to compress or decompress data", context: context)
    }

    // MARK: - Network Errors

    /// Failed to connect to server (BA801)
    public static func connectionError(serverUrl: String? = nil, details: String? = nil) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if serverUrl != nil || details != nil {
            context = [:]
            if let serverUrl { context?["serverUrl"] = AnyCodable(serverUrl) }
            if let details { context?["details"] = AnyCodable(details) }
        }

        return BetterAuthError(code: "BA801", message: "Failed to connect to server", context: context)
    }

    /// Request timed out (BA802)
    public static func timeout(timeoutDuration: Int? = nil, endpoint: String? = nil) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if timeoutDuration != nil || endpoint != nil {
            context = [:]
            if let timeoutDuration { context?["timeoutDuration"] = AnyCodable(timeoutDuration) }
            if let endpoint { context?["endpoint"] = AnyCodable(endpoint) }
        }

        return BetterAuthError(code: "BA802", message: "Request timed out", context: context)
    }

    /// Invalid HTTP response or protocol violation (BA803)
    public static func protocolError(httpStatusCode: Int? = nil, details: String? = nil) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if httpStatusCode != nil || details != nil {
            context = [:]
            if let httpStatusCode { context?["httpStatusCode"] = AnyCodable(httpStatusCode) }
            if let details { context?["details"] = AnyCodable(details) }
        }

        return BetterAuthError(code: "BA803", message: "Invalid HTTP response or protocol violation", context: context)
    }

    // MARK: - Protocol Errors

    /// Operation not allowed in current state (BA901)
    public static func invalidState(
        currentState: String? = nil,
        attemptedOperation: String? = nil,
        requiredState: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if currentState != nil || attemptedOperation != nil || requiredState != nil {
            context = [:]
            if let currentState { context?["currentState"] = AnyCodable(currentState) }
            if let attemptedOperation { context?["attemptedOperation"] = AnyCodable(attemptedOperation) }
            if let requiredState { context?["requiredState"] = AnyCodable(requiredState) }
        }

        return BetterAuthError(code: "BA901", message: "Operation not allowed in current state", context: context)
    }

    /// Key rotation failed (BA902)
    public static func rotationError(rotationType: String? = nil, details: String? = nil) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if rotationType != nil || details != nil {
            context = [:]
            if let rotationType { context?["rotationType"] = AnyCodable(rotationType) }
            if let details { context?["details"] = AnyCodable(details) }
        }

        return BetterAuthError(code: "BA902", message: "Key rotation failed", context: context)
    }

    /// Account recovery failed (BA903)
    public static func recoveryError(details: String? = nil) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if let details {
            context = ["details": AnyCodable(details)]
        }

        return BetterAuthError(code: "BA903", message: "Account recovery failed", context: context)
    }

    /// Device has been revoked (BA904)
    public static func deviceRevoked(
        deviceIdentifier: String? = nil,
        revocationTimestamp: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if deviceIdentifier != nil || revocationTimestamp != nil {
            context = [:]
            if let deviceIdentifier { context?["deviceIdentifier"] = AnyCodable(deviceIdentifier) }
            if let revocationTimestamp { context?["revocationTimestamp"] = AnyCodable(revocationTimestamp) }
        }

        return BetterAuthError(code: "BA904", message: "Device has been revoked", context: context)
    }

    /// Identity has been deleted (BA905)
    public static func identityDeleted(
        identityIdentifier: String? = nil,
        deletionTimestamp: String? = nil
    ) -> BetterAuthError {
        var context: [String: AnyCodable]?
        if identityIdentifier != nil || deletionTimestamp != nil {
            context = [:]
            if let identityIdentifier { context?["identityIdentifier"] = AnyCodable(identityIdentifier) }
            if let deletionTimestamp { context?["deletionTimestamp"] = AnyCodable(deletionTimestamp) }
        }

        return BetterAuthError(code: "BA905", message: "Identity has been deleted", context: context)
    }
}

// MARK: - AnyCodable

/// A type-erased Codable value
public struct AnyCodable: Codable {
    public let value: Any

    public init(_ value: Any) {
        self.value = value
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        if let value = try? container.decode(Bool.self) {
            self.value = value
        } else if let value = try? container.decode(Int.self) {
            self.value = value
        } else if let value = try? container.decode(Double.self) {
            self.value = value
        } else if let value = try? container.decode(String.self) {
            self.value = value
        } else if let value = try? container.decode([String].self) {
            self.value = value
        } else if let value = try? container.decode([String: AnyCodable].self) {
            self.value = value.mapValues { $0.value }
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported type")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()

        switch value {
        case let value as Bool:
            try container.encode(value)
        case let value as Int:
            try container.encode(value)
        case let value as Double:
            try container.encode(value)
        case let value as String:
            try container.encode(value)
        case let value as [String]:
            try container.encode(value)
        case let value as [String: Any]:
            let mapped = value.mapValues { AnyCodable($0) }
            try container.encode(mapped)
        default:
            let context = EncodingError.Context(
                codingPath: container.codingPath,
                debugDescription: "Unsupported type"
            )
            throw EncodingError.invalidValue(value, context)
        }
    }
}
