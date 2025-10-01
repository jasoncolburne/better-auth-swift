import Foundation

public class ClientRequest<T>: SignableMessage {
  public override var payload: Any? {
    get { _payload }
    set { _payload = (newValue as? [String: Any]) ?? _payload }
  }

  private var _payload: [String: Any]

  public init(request: T, nonce: String) {
    _payload = [
      "access": [
        "nonce": nonce
      ],
      "request": request,
    ]
    super.init()
    super.payload = _payload
  }

  public static func parse<U>(
    _ message: String,
    _ constructor: @escaping (U, String) -> ClientRequest<U>
  ) throws -> ClientRequest<U> {
    guard let data = message.data(using: .utf8),
      let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      let payload = json["payload"] as? [String: Any],
      let request = payload["request"] as? U,
      let access = payload["access"] as? [String: Any],
      let nonce = access["nonce"] as? String
    else {
      throw BetterAuthError.invalidData
    }

    let result = constructor(request, nonce)
    result.signature = json["signature"] as? String
    return result
  }
}
