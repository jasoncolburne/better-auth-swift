import Foundation

public class CreateAccountRequest: ClientRequest<[String: Any]> {
    // Constructor matching Dart: CreateAccountRequest(Map<String, dynamic> request, String nonce)
    // Called from Client.swift as: CreateAccountRequest(authentication: [...], nonce: nonce)
    public init(authentication: [String: Any], nonce: String) {
        let request: [String: Any] = [
            "authentication": authentication,
        ]
        super.init(request: request, nonce: nonce)
    }

    public static func parse(_ message: String) throws -> CreateAccountRequest {
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
                messageType: "AccountMessage",
                details: "Missing required fields"
            )
        }

        let result = CreateAccountRequest(authentication: authentication, nonce: nonce)
        result.signature = baseRequest.signature
        return result
    }
}

public class CreateAccountResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> CreateAccountResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            CreateAccountResponse(response: response, serverIdentity: serverIdentity, nonce: nonce)
        } as! CreateAccountResponse
    }
}

public class RecoverAccountRequest: ClientRequest<[String: Any]> {
    public static func parse(_ message: String) throws -> RecoverAccountRequest {
        try ClientRequest<[String: Any]>.parse(message) { request, nonce in
            RecoverAccountRequest(request: request, nonce: nonce)
        } as! RecoverAccountRequest
    }
}

public class RecoverAccountResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> RecoverAccountResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            RecoverAccountResponse(response: response, serverIdentity: serverIdentity, nonce: nonce)
        } as! RecoverAccountResponse
    }
}

public class DeleteAccountRequest: ClientRequest<[String: Any]> {
    public init(authentication: [String: Any], nonce: String) {
        let request: [String: Any] = [
            "authentication": authentication,
        ]
        super.init(request: request, nonce: nonce)
    }

    public static func parse(_ message: String) throws -> DeleteAccountRequest {
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
                messageType: "AccountMessage",
                details: "Missing required fields"
            )
        }

        let result = DeleteAccountRequest(authentication: authentication, nonce: nonce)
        result.signature = baseRequest.signature
        return result
    }
}

public class DeleteAccountResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> DeleteAccountResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            DeleteAccountResponse(response: response, serverIdentity: serverIdentity, nonce: nonce)
        } as! DeleteAccountResponse
    }
}
