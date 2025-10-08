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
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            LinkDeviceResponse(response: response, serverIdentity: serverIdentity, nonce: nonce)
        } as! LinkDeviceResponse
    }
}

public class UnlinkDeviceRequest: ClientRequest<[String: Any]> {
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

    public static func parse(_ message: String) throws -> UnlinkDeviceRequest {
        try ClientRequest<[String: Any]>.parse(message) { request, nonce in
            UnlinkDeviceRequest(request: request, nonce: nonce)
        } as! UnlinkDeviceRequest
    }
}

public class UnlinkDeviceResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> UnlinkDeviceResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            UnlinkDeviceResponse(response: response, serverIdentity: serverIdentity, nonce: nonce)
        } as! UnlinkDeviceResponse
    }
}

public class RotateDeviceRequest: ClientRequest<[String: Any]> {
    // Constructor matching Dart: RotateDeviceRequest(Map<String, dynamic> request, String nonce)
    // Called from Client.swift as: RotateDeviceRequest(authentication: [...], nonce: nonce)
    public init(authentication: [String: Any], nonce: String) {
        let request: [String: Any] = [
            "authentication": authentication,
        ]
        super.init(request: request, nonce: nonce)
    }

    public static func parse(_ message: String) throws -> RotateDeviceRequest {
        let baseRequest = try ClientRequest<[String: Any]>.parse(message) { request, nonce in
            ClientRequest<[String: Any]>(request: request, nonce: nonce)
        }

        guard let payload = baseRequest.payload as? [String: Any],
              let request = payload["request"] as? [String: Any],
              let authentication = request["authentication"] as? [String: Any],
              let access = payload["access"] as? [String: Any],
              let nonce = access["nonce"] as? String
        else {
            throw BetterAuthError.invalidData
        }

        let result = RotateDeviceRequest(authentication: authentication, nonce: nonce)
        result.signature = baseRequest.signature
        return result
    }
}

public class RotateDeviceResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> RotateDeviceResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            RotateDeviceResponse(
                response: response, serverIdentity: serverIdentity, nonce: nonce
            )
        } as! RotateDeviceResponse
    }
}
