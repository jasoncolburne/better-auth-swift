import Foundation

open class ServerResponse<T>: SignableMessage {
    override public var payload: Any? {
        get { _payload }
        set { _payload = (newValue as? [String: Any]) ?? _payload }
    }

    private var _payload: [String: Any]

    public init(response: T, serverIdentity: String, nonce: String) {
        _payload = [
            "access": [
                "nonce": nonce,
                "serverIdentity": serverIdentity,
            ],
            "response": response,
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
              let serverIdentity = access["serverIdentity"] as? String,
              let nonce = access["nonce"] as? String
        else {
            throw BetterAuthError.deserializationError(
                messageType: "ResponseMessage",
                details: "Missing required fields"
            )
        }

        let result = constructor(response, serverIdentity, nonce)
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
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            ScannableResponse(response: response, serverIdentity: serverIdentity, nonce: nonce)
        } as! ScannableResponse
    }
}
