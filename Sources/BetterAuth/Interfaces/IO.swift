import Foundation

public protocol INetwork {
  func sendRequest(_ path: String, _ message: String) async throws -> String
}
