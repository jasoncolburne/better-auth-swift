import Foundation

public class RefreshAccessTokenRequest: ClientRequest<[String: Any]> {
    override public init(request: [String: Any], nonce: String) {
        super.init(request: request, nonce: nonce)
    }

    public static func parse(_ message: String) throws -> RefreshAccessTokenRequest {
        try ClientRequest<[String: Any]>.parse(message) { request, nonce in
            RefreshAccessTokenRequest(request: request, nonce: nonce)
        } as! RefreshAccessTokenRequest
    }
}

public class RefreshAccessTokenResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> RefreshAccessTokenResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, publicKeyHash, nonce in
            RefreshAccessTokenResponse(response: response, responseKeyHash: publicKeyHash, nonce: nonce)
        } as! RefreshAccessTokenResponse
    }
}
