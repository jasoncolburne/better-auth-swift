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
}
