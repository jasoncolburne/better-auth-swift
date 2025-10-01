import Foundation

public class RecoverAccountRequest: ClientRequest<[String: Any]> {
    public static func parse(_ message: String) throws -> RecoverAccountRequest {
        try ClientRequest<[String: Any]>.parse(message) { request, nonce in
            RecoverAccountRequest(request: request, nonce: nonce)
        } as! RecoverAccountRequest
    }
}

public class RecoverAccountResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> RecoverAccountResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, publicKeyHash, nonce in
            RecoverAccountResponse(response: response, responseKeyHash: publicKeyHash, nonce: nonce)
        } as! RecoverAccountResponse
    }
}
