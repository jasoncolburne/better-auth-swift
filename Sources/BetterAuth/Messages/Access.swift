import Foundation

public class AccessToken<T>: SignableMessage {
    public let identity: String
    public let publicKey: String
    public let rotationHash: String
    public let issuedAt: String
    public let expiry: String
    public let refreshExpiry: String
    public let attributes: T

    private var _payload: [String: Any]

    override public var payload: Any? {
        get { _payload }
        set { _payload = newValue as? [String: Any] ?? _payload }
    }

    public init(
        identity: String,
        publicKey: String,
        rotationHash: String,
        issuedAt: String,
        expiry: String,
        refreshExpiry: String,
        attributes: T
    ) {
        self.identity = identity
        self.publicKey = publicKey
        self.rotationHash = rotationHash
        self.issuedAt = issuedAt
        self.expiry = expiry
        self.refreshExpiry = refreshExpiry
        self.attributes = attributes

        _payload = [
            "identity": identity,
            "publicKey": publicKey,
            "rotationHash": rotationHash,
            "issuedAt": issuedAt,
            "expiry": expiry,
            "refreshExpiry": refreshExpiry,
            "attributes": attributes,
        ]

        super.init()
        super.payload = _payload
    }

    public static func parse(
        _ message: String,
        _ publicKeyLength: Int,
        _ tokenEncoder: any ITokenEncoder
    ) async throws -> AccessToken<T> {
        let signature = String(message.prefix(publicKeyLength))
        let rest = String(message.dropFirst(publicKeyLength))

        let tokenString = try await tokenEncoder.decode(rest)
        guard let data = tokenString.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let identity = json["identity"] as? String,
              let publicKey = json["publicKey"] as? String,
              let rotationHash = json["rotationHash"] as? String,
              let issuedAt = json["issuedAt"] as? String,
              let expiry = json["expiry"] as? String,
              let refreshExpiry = json["refreshExpiry"] as? String,
              let attributes = json["attributes"] as? T
        else {
            throw BetterAuthError.invalidData
        }

        let token = AccessToken<T>(
            identity: identity,
            publicKey: publicKey,
            rotationHash: rotationHash,
            issuedAt: issuedAt,
            expiry: expiry,
            refreshExpiry: refreshExpiry,
            attributes: attributes
        )

        token.signature = signature
        return token
    }

    override public func composePayload() throws -> String {
        let jsonData = try JSONSerialization.data(withJSONObject: _payload, options: [.sortedKeys])
        return String(data: jsonData, encoding: .utf8)!
    }

    public func serializeToken(_ tokenEncoder: any ITokenEncoder) async throws -> String {
        guard let signature else {
            throw BetterAuthError.nullSignature
        }
        let token = try await tokenEncoder.encode(composePayload())
        return signature + token
    }

    public func verifyToken(
        _ verifier: any IVerifier,
        _ publicKey: String,
        _ timestamper: any ITimestamper
    ) async throws {
        try await verify(verifier, publicKey)

        let now = timestamper.now()
        let issuedAtTime = try timestamper.parse(issuedAt)
        let expiryTime = try timestamper.parse(expiry)

        if now < issuedAtTime {
            throw BetterAuthError.tokenFromFuture
        }

        if now > expiryTime {
            throw BetterAuthError.tokenExpired
        }
    }
}

public class AccessRequest<T>: SignableMessage {
    private var _payload: [String: Any]

    override public var payload: Any? {
        get { _payload }
        set { _payload = newValue as? [String: Any] ?? _payload }
    }

    // Constructor matching Dart: AccessRequest(Map<String, dynamic> payload)
    // Called from Client.swift as: AccessRequest<T>(access: [...], request: request)
    public init(access: [String: Any], request: T) {
        _payload = [
            "access": access,
            "request": request,
        ]
        super.init()
        super.payload = _payload
    }

    private init(payload: [String: Any]) {
        _payload = payload
        super.init()
        super.payload = _payload
    }

    public func internalVerify<A>(
        _ nonceStore: any IServerTimeLockStore,
        _ verifier: any IVerifier,
        _ tokenVerifier: any IVerifier,
        _ serverAccessPublicKey: String,
        _ tokenEncoder: any ITokenEncoder,
        _ timestamper: any ITimestamper
    ) async throws -> (String, A) {
        guard let access = _payload["access"] as? [String: Any],
              let tokenString = access["token"] as? String,
              let timestamp = access["timestamp"]
        else {
            throw BetterAuthError.invalidData
        }

        let accessToken = try await AccessToken<A>.parse(
            tokenString,
            tokenVerifier.signatureLength,
            tokenEncoder
        )

        try await accessToken.verifyToken(
            tokenVerifier,
            serverAccessPublicKey,
            timestamper
        )
        try await verify(verifier, accessToken.publicKey)

        let now = timestamper.now()
        let accessTime = try timestamper.parse(timestamp)
        let expiryWithLifetime = Calendar.current.date(
            byAdding: .second,
            value: nonceStore.lifetimeInSeconds,
            to: accessTime
        )!

        if now > expiryWithLifetime {
            throw BetterAuthError.staleRequest
        }

        if now < accessTime {
            throw BetterAuthError.requestFromFuture
        }

        guard let nonce = access["nonce"] as? String else {
            throw BetterAuthError.invalidData
        }
        try await nonceStore.reserve(nonce)

        return (accessToken.identity, accessToken.attributes)
    }

    public static func parse(_ message: String) throws -> AccessRequest<T> {
        guard let data = message.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let payload = json["payload"] as? [String: Any]
        else {
            throw BetterAuthError.invalidData
        }
        let result = AccessRequest<T>(payload: payload)
        result.signature = json["signature"] as? String
        return result
    }
}
