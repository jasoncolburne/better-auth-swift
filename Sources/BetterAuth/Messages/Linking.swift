import Foundation

public class LinkContainer: SignableMessage {
    private var _payload: [String: Any]

    override public var payload: Any? {
        get { _payload }
        set { _payload = newValue as? [String: Any] ?? _payload }
    }

    // Constructor matching Dart: LinkContainer(Map<String, dynamic> payload)
    public init(payload: [String: Any]) {
        _payload = payload
        super.init()
        super.payload = _payload
    }

    // Convenience initializer for easier construction
    public convenience init(authentication: [String: Any]) {
        let payload: [String: Any] = [
            "authentication": authentication,
        ]
        self.init(payload: payload)
    }

    override public func composePayload() throws -> String {
        let jsonData = try JSONSerialization.data(withJSONObject: _payload, options: [.sortedKeys])
        return String(data: jsonData, encoding: .utf8)!
    }

    public func toJSON() -> [String: Any] {
        [
            "payload": _payload,
            "signature": signature as Any,
        ]
    }

    public static func parse(_ message: String) throws -> LinkContainer {
        guard let data = message.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let payload = json["payload"] as? [String: Any]
        else {
            throw BetterAuthError.invalidData
        }
        let result = LinkContainer(payload: payload)
        result.signature = json["signature"] as? String
        return result
    }
}

public class LinkDeviceRequest: ClientRequest<[String: Any]> {
    // Constructor matching Dart: LinkDeviceRequest(Map<String, dynamic> request, String nonce)
    override public init(request: [String: Any], nonce: String) {
        super.init(request: request, nonce: nonce)
    }

    // Convenience initializer for easier construction
    public convenience init(authentication: [String: Any], link: [String: Any], nonce: String) {
        let request: [String: Any] = [
            "authentication": authentication,
            "link": link,
        ]
        self.init(request: request, nonce: nonce)
    }

    public static func parse(_ message: String) throws -> LinkDeviceRequest {
        try ClientRequest<[String: Any]>.parse(message) { request, nonce in
            LinkDeviceRequest(request: request, nonce: nonce)
        } as! LinkDeviceRequest
    }
}

public class LinkDeviceResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> LinkDeviceResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, publicKeyHash, nonce in
            LinkDeviceResponse(response: response, responseKeyHash: publicKeyHash, nonce: nonce)
        } as! LinkDeviceResponse
    }
}
