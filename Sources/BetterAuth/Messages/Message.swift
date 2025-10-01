import Foundation

public protocol SerializableMessage {
    func serialize() async throws -> String
}

open class SignableMessage: SerializableMessage {
    public var payload: Any?
    public var signature: String?
    public var originalPayloadString: String?

    public init() {}

    open func composePayload() throws -> String {
        guard let payload else {
            throw BetterAuthError.payloadNotDefined
        }
        let jsonData = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        return String(data: jsonData, encoding: .utf8)!
    }

    public func serialize() async throws -> String {
        guard let signature else {
            throw BetterAuthError.nullSignature
        }
        let payloadString = try composePayload()
        return "{\"payload\":\(payloadString),\"signature\":\"\(signature)\"}"
    }

    public func sign(_ signer: any ISigningKey) async throws {
        signature = try await signer.sign(composePayload())
    }

    public func verify(_ verifier: any IVerifier, _ publicKey: String) async throws {
        guard let signature else {
            throw BetterAuthError.nullSignature
        }
        let payloadToVerify = try originalPayloadString ?? composePayload()
        try await verifier.verify(payloadToVerify, signature, publicKey)
    }
}

public enum BetterAuthError: Error {
    case payloadNotDefined
    case nullSignature
    case hashMismatch
    case incorrectNonce
    case invalidData
    case keypairNotGenerated
    case nothingToGet
    case callInitializeFirst
    case tokenFromFuture
    case tokenExpired
    case staleRequest
    case requestFromFuture
}
