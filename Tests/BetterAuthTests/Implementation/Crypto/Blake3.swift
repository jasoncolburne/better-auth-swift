import BLAKE3
import Foundation

enum Blake3 {
    static func sum256(_ bytes: Data) async -> Data {
        Data(BLAKE3.hash(contentsOf: bytes))
    }
}
