import Foundation

@testable import BetterAuth

class Rfc3339: ITimestamper {
    func format(_ when: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        // withFractionalSeconds gives milliseconds (3 digits) by default in RFC3339 format
        return formatter.string(from: when)
    }

    func parse(_ when: Any) throws -> Date {
        if let date = when as? Date {
            return date
        }
        guard let string = when as? String else {
            throw NSError(domain: "BetterAuth", code: 3, userInfo: [NSLocalizedDescriptionKey: "Deserialization error"])
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: string) else {
            throw NSError(domain: "BetterAuth", code: 3, userInfo: [NSLocalizedDescriptionKey: "Deserialization error"])
        }
        return date
    }

    func now() -> Date {
        Date()
    }
}
