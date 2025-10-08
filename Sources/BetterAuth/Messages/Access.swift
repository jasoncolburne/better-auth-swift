import Foundation

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
