import Foundation

@testable import BetterAuth

class ClientRotatingKeyStore: IClientRotatingKeyStore {
    private var currentKey: (any ISigningKey)?
    private var nextKey: (any ISigningKey)?
    private var futureKey: (any ISigningKey)?
    private let hasher = Hasher()

    func initialize(_ extraData: String?) async throws -> (String, String, String) {
        let current = Secp256r1()
        let next = Secp256r1()

        await current.generate()
        await next.generate()

        currentKey = current
        nextKey = next

        let suffix = extraData ?? ""

        let publicKey = try await current.public()
        let rotationHash = try await hasher.sum(next.public())
        let identity = try await hasher.sum(publicKey + rotationHash + suffix)

        return (identity, publicKey, rotationHash)
    }

    func next() async throws -> (any ISigningKey, String) {
        guard let nextKey else {
            throw BetterAuthError.invalidState(currentState: "uninitialized", attemptedOperation: "next/rotate/signer", requiredState: "initialized")
        }

        if futureKey == nil {
            let key = Secp256r1()
            await key.generate()
            futureKey = key
        }

        let rotationHash = try await hasher.sum(futureKey!.public())

        return (nextKey, rotationHash)
    }

    func rotate() async throws {
        guard let nextKey else {
            throw BetterAuthError.invalidState(currentState: "uninitialized", attemptedOperation: "next/rotate/signer", requiredState: "initialized")
        }

        guard let futureKey else {
            throw BetterAuthError.invalidState(currentState: "next not called", attemptedOperation: "rotate", requiredState: "next called")
        }

        currentKey = nextKey
        self.nextKey = futureKey
        self.futureKey = nil
    }

    func signer() async throws -> any ISigningKey {
        guard let currentKey else {
            throw BetterAuthError.invalidState(currentState: "uninitialized", attemptedOperation: "next/rotate/signer", requiredState: "initialized")
        }

        return currentKey
    }
}

class ClientValueStore: IClientValueStore {
    private var value: String?

    func store(_ value: String) async throws {
        self.value = value
    }

    func get() async throws -> String {
        guard let value else {
            throw BetterAuthError.notFound(resourceType: "stored value")
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
