import Foundation
import OrderedCollections

public class AccessRequest<T>: SignableMessage {
    private var _payload: [String: Any]
    private var cachedRequestString: String?

    override public var payload: Any? {
        get { _payload }
        set { _payload = newValue as? [String: Any] ?? _payload }
    }

    // Helper function to serialize objects to JSON, handling OrderedDictionary specially
    private func serializeToJSON(_ object: Any) throws -> String {
        // Check if it's an OrderedDictionary<String, String>
        if let orderedDict = object as? OrderedDictionary<String, String> {
            // Manually build JSON string to preserve order
            let pairs = orderedDict.map { key, value in
                let escapedKey = key.replacingOccurrences(of: "\\", with: "\\\\")
                    .replacingOccurrences(of: "\"", with: "\\\"")
                let escapedValue = value.replacingOccurrences(of: "\\", with: "\\\\")
                    .replacingOccurrences(of: "\"", with: "\\\"")
                return "\"\(escapedKey)\":\"\(escapedValue)\""
            }
            return "{\(pairs.joined(separator: ","))}"
        }

        // Fall back to JSONSerialization for other types
        let data = try JSONSerialization.data(withJSONObject: object, options: [])
        return String(data: data, encoding: .utf8)!
    }

    // Constructor matching Dart: AccessRequest(Map<String, dynamic> payload)
    // Called from Client.swift as: AccessRequest<T>(access: [...], request: request)
    public init(access: [String: Any], request: T) async throws {
        _payload = [
            "access": access,
            "request": request,
        ]
        super.init()
        super.payload = _payload

        // Cache the request string immediately to ensure consistent serialization
        cachedRequestString = try serializeToJSON(request)
    }

    private init(payload: [String: Any]) {
        _payload = payload
        super.init()
        super.payload = _payload
    }

    override open func composePayload() throws -> String {
        guard let payload = _payload["access"] else {
            throw BetterAuthError.payloadNotDefined
        }
        let accessData = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        let accessString = String(data: accessData, encoding: .utf8)!

        // Use the cached request string (cached in init)
        guard let requestString = cachedRequestString else {
            throw BetterAuthError.payloadNotDefined
        }

        return "{\"access\":\(accessString),\"request\":\(requestString)}"
    }
}
