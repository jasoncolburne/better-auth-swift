import Foundation

public class ServerResponse<T>: SignableMessage {
    override public var payload: Any? {
        get { _payload }
        set { _payload = (newValue as? [String: Any]) ?? _payload }
    }

    private var _payload: [String: Any]

    public init(response: T, responseKeyHash: String, nonce: String) {
        _payload = [
            "access": [
                "nonce": nonce,
                "responseKeyHash": responseKeyHash
            ],
            "response": response
        ]
        super.init()
        super.payload = _payload
    }

    public static func parse<U>(
        _ message: String,
        _ constructor: @escaping (U, String, String) -> ServerResponse<U>
    ) throws -> ServerResponse<U> {
        guard let data = message.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let payload = json["payload"] as? [String: Any],
              let access = payload["access"] as? [String: Any],
              let response = payload["response"] as? U,
              let responseKeyHash = access["responseKeyHash"] as? String,
              let nonce = access["nonce"] as? String
        else {
            throw BetterAuthError.invalidData
        }

        let result = constructor(response, responseKeyHash, nonce)
        result.signature = json["signature"] as? String

        // Extract the original payload string from the message for verification
        // This preserves the exact serialization (including key order) that was signed by the server
        if let range = message.range(of: "\"payload\":"),
           let endRange = message.range(of: ",\"signature\":", range: range.upperBound ..< message.endIndex) {
            result.originalPayloadString = String(message[range.upperBound ..< endRange.lowerBound])
        }

        return result
    }
}

public class ScannableResponse: ServerResponse<[String: Any]> {
    public static func parse(_ message: String) throws -> ScannableResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, publicKeyHash, nonce in
            ScannableResponse(response: response, responseKeyHash: publicKeyHash, nonce: nonce)
        } as! ScannableResponse
    }
}
