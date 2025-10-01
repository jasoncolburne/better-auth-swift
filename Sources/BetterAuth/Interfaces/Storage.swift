import Foundation

// Client-side storage interfaces
public protocol IClientValueStore {
    func store(_ value: String) async throws
    func get() async throws -> String
}

public protocol IClientRotatingKeyStore {
    func initialize(_ extraData: String?) async throws -> [String]
    func rotate() async throws -> [String]
    func signer() async throws -> any ISigningKey
}

// Server-side storage interfaces
public protocol IServerAuthenticationNonceStore {
    var lifetimeInSeconds: Int { get }
    func generate(_ identity: String) async throws -> String
    func validate(_ nonce: String) async throws -> String
}

public protocol IServerAuthenticationKeyStore {
    func register(
        _ identity: String, _ device: String, _ publicKey: String, _ rotationHash: String,
        _ existingIdentity: Bool
    ) async throws
    func rotate(_ identity: String, _ device: String, _ current: String, _ rotationHash: String)
        async throws
    func `public`(_ identity: String, _ device: String) async throws -> String
}

public protocol IServerRecoveryHashStore {
    func register(_ identity: String, _ keyHash: String) async throws
    func validate(_ identity: String, _ keyHash: String) async throws
}

public protocol IServerTimeLockStore {
    var lifetimeInSeconds: Int { get }
    func reserve(_ value: String) async throws
}
