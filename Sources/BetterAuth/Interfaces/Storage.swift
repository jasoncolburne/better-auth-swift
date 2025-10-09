import Foundation

// Client-side storage interfaces
public protocol IClientValueStore {
    func store(_ value: String) async throws
    func get() async throws -> String
}

public protocol IClientRotatingKeyStore {
    func initialize(_ extraData: String?) async throws -> [String]

    // returns: [key, rotationHash]
    //
    // this should return the _next_ signing key and a hash of the subsequent key
    // if no subsequent key exists yet, it should first be generated
    //
    // this facilitates a failed network request during a rotation operation
    func next() async throws -> [Any]

    // throw an exception if:
    // - next() has not been called since the last call to initialize() or rotate()
    //
    // this is the commit operation of next()
    func rotate() async throws

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

public protocol IVerificationKeyStore {
    func get(identity: String) async throws -> any IVerificationKey
}
