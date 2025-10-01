import Foundation

@testable import BetterAuth

class Rfc3339Nano: ITimestamper {
  func format(_ when: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let isoString = formatter.string(from: when)
    return isoString.replacingOccurrences(of: "Z", with: "000000Z")
  }

  func parse(_ when: Any) throws -> Date {
    if let date = when as? Date {
      return date
    }
    guard let string = when as? String else {
      throw BetterAuthError.invalidData
    }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    guard let date = formatter.date(from: string) else {
      throw BetterAuthError.invalidData
    }
    return date
  }

  func now() -> Date {
    return Date()
  }
}
