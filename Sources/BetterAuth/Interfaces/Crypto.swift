import Foundation

public protocol IHasher {
  func sum(_ message: String) async throws -> String
}

public protocol INoncer {
  func generate128() async throws -> String
}

public protocol IVerifier {
  var signatureLength: Int { get }
  func verify(_ message: String, _ signature: String, _ publicKey: String) async throws
}

public protocol IVerificationKey {
  func `public`() async throws -> String
  func verifier() -> any IVerifier
  func verify(_ message: String, _ signature: String) async throws
}

public protocol ISigningKey: IVerificationKey {
  func sign(_ message: String) async throws -> String
}
