import BLAKE3
import Foundation

struct Blake3 {
  static func sum256(_ bytes: Data) async -> Data {
    return Data(BLAKE3.hash(contentsOf: bytes))
  }
}
