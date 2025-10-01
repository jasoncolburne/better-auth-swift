import Crypto
import Foundation

@testable import BetterAuth

class Secp256r1Verifier: IVerifier {
    var signatureLength: Int { 88 }

    func verify(_ message: String, _ signature: String, _ publicKey: String) async throws {
        let publicKeyBytes = Base64.decode(publicKey).dropFirst(3)
        let signatureBytes = Base64.decode(signature).dropFirst(2)
        let messageBytes = message.data(using: .utf8)!

        let key = try P256.Signing.PublicKey(compressedRepresentation: publicKeyBytes)
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: signatureBytes)

        guard key.isValidSignature(sig, for: messageBytes) else {
            throw BetterAuthError.invalidData
        }
    }
}

class Secp256r1: ISigningKey {
    private var keyPair: P256.Signing.PrivateKey?
    private let _verifier = Secp256r1Verifier()

    func generate() async {
        keyPair = P256.Signing.PrivateKey()
    }

    func sign(_ message: String) async throws -> String {
        guard let keyPair else {
            throw BetterAuthError.keypairNotGenerated
        }

        let messageBytes = message.data(using: .utf8)!
        let signature = try keyPair.signature(for: messageBytes)
        let signatureBytes = signature.rawRepresentation

        var paddedBytes = Data([0, 0])
        paddedBytes.append(signatureBytes)
        let base64 = Base64.encode(paddedBytes)

        return "0I" + base64.dropFirst(2)
    }

    func `public`() async throws -> String {
        guard let keyPair else {
            throw BetterAuthError.keypairNotGenerated
        }

        let publicKey = keyPair.publicKey
        let compressed = publicKey.compressedRepresentation

        var paddedBytes = Data([0, 0, 0])
        paddedBytes.append(compressed)
        let base64 = Base64.encode(paddedBytes)

        return "1AAI" + base64.dropFirst(4)
    }

    func verifier() -> any IVerifier {
        _verifier
    }

    func verify(_ message: String, _ signature: String) async throws {
        try await _verifier.verify(message, signature, self.public())
    }
}
