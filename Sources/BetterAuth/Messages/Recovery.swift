import Foundation

public class ChangeRecoveryKeyRequest: ClientRequest<[String: Any]> {
    public init(authentication: [String: Any], nonce: String) {
        let request: [String: Any] = [
            "authentication": authentication,
        ]
        super.init(request: request, nonce: nonce)
    }

    public static func parse(_ message: String) throws -> ChangeRecoveryKeyRequest {
        let baseRequest = try ClientRequest<[String: Any]>.parse(message) { request, nonce in
            ClientRequest<[String: Any]>(request: request, nonce: nonce)
        }

        guard let payload = baseRequest.payload as? [String: Any],
              let request = payload["request"] as? [String: Any],
              let authentication = request["authentication"] as? [String: Any],
              let access = payload["access"] as? [String: Any],
              let nonce = access["nonce"] as? String
        else {
            throw BetterAuthError.deserializationError(
                messageType: "RecoveryMessage",
                details: "Missing required fields"
            )
        }

        let result = ChangeRecoveryKeyRequest(authentication: authentication, nonce: nonce)
        result.signature = baseRequest.signature
        return result
    }
}

public class ChangeRecoveryKeyResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> ChangeRecoveryKeyResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            ChangeRecoveryKeyResponse(response: response, serverIdentity: serverIdentity, nonce: nonce)
        } as! ChangeRecoveryKeyResponse
    }
}
