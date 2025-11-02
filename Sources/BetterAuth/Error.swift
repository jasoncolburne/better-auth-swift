import Foundation

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
}

// MARK: - Storage, Network, and Protocol Errors - Removed (unused in client implementation)

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
