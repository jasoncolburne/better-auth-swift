import Foundation

public protocol ITimestamper {
  func format(_ when: Date) -> String
  func parse(_ when: Any) throws -> Date
  func now() -> Date
}

public protocol ITokenEncoder {
  func encode(_ object: String) async throws -> String
  func decode(_ rawToken: String) async throws -> String
}

public protocol IIdentityVerifier {
  func verify(_ identity: String, _ publicKey: String, _ rotationHash: String, _ extraData: String?)
    async throws
}
