import Foundation

public class StartAuthenticationRequest: SerializableMessage {
  public let payload: [String: Any]

  // Constructor matching Dart: StartAuthenticationRequest(Map<String, dynamic> payload)
  // Called from Client.swift as: StartAuthenticationRequest(access: [...], request: [...])
  public init(access: [String: Any], request: [String: Any]) {
    self.payload = [
      "access": access,
      "request": request,
    ]
  }

  private init(payload: [String: Any]) {
    self.payload = payload
  }

  public func serialize() async throws -> String {
    let json: [String: Any] = [
      "payload": payload
    ]
    let jsonData = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])
    return String(data: jsonData, encoding: .utf8)!
  }

  public static func parse(_ message: String) throws -> StartAuthenticationRequest {
    guard let data = message.data(using: .utf8),
      let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      let payload = json["payload"] as? [String: Any]
    else {
      throw BetterAuthError.invalidData
    }
    return StartAuthenticationRequest(payload: payload)
  }
}

public class StartAuthenticationResponse: ServerResponse<[String: Any]> {
  public static func parse(_ message: String) throws -> StartAuthenticationResponse {
    return try ServerResponse<[String: Any]>.parse(message) { response, publicKeyHash, nonce in
      StartAuthenticationResponse(response: response, responseKeyHash: publicKeyHash, nonce: nonce)
    } as! StartAuthenticationResponse
  }
}

public class FinishAuthenticationRequest: ClientRequest<[String: Any]> {
  // Constructor matching Dart: FinishAuthenticationRequest(Map<String, dynamic> request, String nonce)
  // Called from Client.swift as: FinishAuthenticationRequest(access: [...], authentication: [...], nonce: nonce)
  public init(access: [String: Any], authentication: [String: Any], nonce: String) {
    let request: [String: Any] = [
      "access": access,
      "authentication": authentication,
    ]
    super.init(request: request, nonce: nonce)
  }

  public static func parse(_ message: String) throws -> FinishAuthenticationRequest {
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
      throw BetterAuthError.invalidData
    }

    let result = FinishAuthenticationRequest(access: access, authentication: auth, nonce: nonce)
    result.signature = baseRequest.signature
    return result
  }
}

public class FinishAuthenticationResponse: ServerResponse<[String: Any]> {
  public static func parse(_ message: String) throws -> FinishAuthenticationResponse {
    return try ServerResponse<[String: Any]>.parse(message) { response, publicKeyHash, nonce in
      FinishAuthenticationResponse(response: response, responseKeyHash: publicKeyHash, nonce: nonce)
    } as! FinishAuthenticationResponse
  }
}
