import Foundation

@testable import BetterAuth

class ClientRotatingKeyStore: IClientRotatingKeyStore {
    private var current: (any ISigningKey)?
    private var next: (any ISigningKey)?
    private let hasher = Hasher()

    func initialize(_ extraData: String?) async throws -> [String] {
        let current = Secp256r1()
        let next = Secp256r1()

        await current.generate()
        await next.generate()

        self.current = current
        self.next = next

        let suffix = extraData ?? ""

        let publicKey = try await current.public()
        let rotationHash = try await hasher.sum(next.public())
        let identity = try await hasher.sum(publicKey + rotationHash + suffix)

        return [identity, publicKey, rotationHash]
    }

    func rotate() async throws -> [String] {
        guard let next else {
            throw BetterAuthError.callInitializeFirst
        }

        let newNext = Secp256r1()
        await newNext.generate()

        current = next
        self.next = newNext

        let rotationHash = try await hasher.sum(newNext.public())

        return try await [current!.public(), rotationHash]
    }

    func signer() async throws -> any ISigningKey {
        guard let current else {
            throw BetterAuthError.callInitializeFirst
        }

        return current
    }
}

class ClientValueStore: IClientValueStore {
    private var value: String?

    func store(_ value: String) async throws {
        self.value = value
    }

    func get() async throws -> String {
        guard let value else {
            throw BetterAuthError.nothingToGet
        }

        return value
    }
}

class VerificationKeyStore: IVerificationKeyStore {
    private let verificationKey: any IVerificationKey

    init(_ verificationKey: any IVerificationKey) {
        self.verificationKey = verificationKey
    }

    func get(identity _: String) async throws -> any IVerificationKey {
        verificationKey
    }
}
