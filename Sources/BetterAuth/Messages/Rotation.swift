import Foundation

public class RotateAuthenticationKeyRequest: ClientRequest<[String: Any]> {
    // Constructor matching Dart: RotateAuthenticationKeyRequest(Map<String, dynamic> request, String nonce)
    // Called from Client.swift as: RotateAuthenticationKeyRequest(authentication: [...], nonce: nonce)
    public init(authentication: [String: Any], nonce: String) {
        let request: [String: Any] = [
            "authentication": authentication,
        ]
        super.init(request: request, nonce: nonce)
    }

    public static func parse(_ message: String) throws -> RotateAuthenticationKeyRequest {
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

        let result = RotateAuthenticationKeyRequest(authentication: authentication, nonce: nonce)
        result.signature = baseRequest.signature
        return result
    }
}

public class RotateAuthenticationKeyResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> RotateAuthenticationKeyResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            RotateAuthenticationKeyResponse(
                response: response, serverIdentity: serverIdentity, nonce: nonce
            )
        } as! RotateAuthenticationKeyResponse
    }
}
