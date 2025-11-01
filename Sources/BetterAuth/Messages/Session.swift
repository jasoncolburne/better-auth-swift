import Foundation

public class RequestSessionRequest: SerializableMessage {
    public let payload: [String: Any]

    // Constructor matching Dart: RequestSessionRequest(Map<String, dynamic> payload)
    // Called from Client.swift as: RequestSessionRequest(access: [...], request: [...])
    public init(access: [String: Any], request: [String: Any]) {
        payload = [
            "access": access,
            "request": request,
        ]
    }

    private init(payload: [String: Any]) {
        self.payload = payload
    }

    public func serialize() async throws -> String {
        let json: [String: Any] = [
            "payload": payload,
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])
        return String(data: jsonData, encoding: .utf8)!
    }

    public static func parse(_ message: String) throws -> RequestSessionRequest {
        guard let data = message.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let payload = json["payload"] as? [String: Any]
        else {
            throw BetterAuthError.deserializationError(
                messageType: "SessionMessage",
                details: "Missing required fields"
            )
        }
        return RequestSessionRequest(payload: payload)
    }
}

public class RequestSessionResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> RequestSessionResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            RequestSessionResponse(response: response, serverIdentity: serverIdentity, nonce: nonce)
        } as! RequestSessionResponse
    }
}

public class CreateSessionRequest: ClientRequest<[String: Any]> {
    // Constructor matching Dart: CreateSessionRequest(Map<String, dynamic> request, String nonce)
    // Called from Client.swift as: CreateSessionRequest(access: [...], authentication: [...], nonce: nonce)
    public init(access: [String: Any], authentication: [String: Any], nonce: String) {
        let request: [String: Any] = [
            "access": access,
            "authentication": authentication,
        ]
        super.init(request: request, nonce: nonce)
    }

    public static func parse(_ message: String) throws -> CreateSessionRequest {
        // First parse the base request
        let baseRequest = try ClientRequest<[String: Any]>.parse(message) { request, nonce in
            // Return a temporary ClientRequest - we'll validate and reconstruct below
            ClientRequest<[String: Any]>(request: request, nonce: nonce)
        }

        // Extract the payload and validate structure
        guard let payload = baseRequest.payload as? [String: Any],
              let request = payload["request"] as? [String: Any],
              let accessPayload = payload["access"] as? [String: Any],
              let nonce = accessPayload["nonce"] as? String,
              let access = request["access"] as? [String: Any],
              let auth = request["authentication"] as? [String: Any]
        else {
            throw BetterAuthError.deserializationError(
                messageType: "SessionMessage",
                details: "Missing required fields"
            )
        }

        let result = CreateSessionRequest(access: access, authentication: auth, nonce: nonce)
        result.signature = baseRequest.signature
        return result
    }
}

public class CreateSessionResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> CreateSessionResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            CreateSessionResponse(response: response, serverIdentity: serverIdentity, nonce: nonce)
        } as! CreateSessionResponse
    }
}

public class RefreshSessionRequest: ClientRequest<[String: Any]> {
    override public init(request: [String: Any], nonce: String) {
        super.init(request: request, nonce: nonce)
    }

    public static func parse(_ message: String) throws -> RefreshSessionRequest {
        try ClientRequest<[String: Any]>.parse(message) { request, nonce in
            RefreshSessionRequest(request: request, nonce: nonce)
        } as! RefreshSessionRequest
    }
}

public class RefreshSessionResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> RefreshSessionResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            RefreshSessionResponse(response: response, serverIdentity: serverIdentity, nonce: nonce)
        } as! RefreshSessionResponse
    }
}
