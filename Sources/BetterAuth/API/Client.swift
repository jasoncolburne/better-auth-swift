import Foundation

public class BetterAuthClient {
    private let hasher: any IHasher
    private let noncer: any INoncer
    private let verificationKeyStore: any IVerificationKeyStore
    private let timestamper: any ITimestamper
    private let network: any INetwork
    private let paths: IAuthenticationPaths
    private let deviceIdentifierStore: any IClientValueStore
    private let identityIdentifierStore: any IClientValueStore
    private let accessKeyStore: any IClientRotatingKeyStore
    private let authenticationKeyStore: any IClientRotatingKeyStore
    private let accessTokenStore: any IClientValueStore

    public init(
        hasher: any IHasher,
        noncer: any INoncer,
        verificationKeyStore: any IVerificationKeyStore,
        timestamper: any ITimestamper,
        network: any INetwork,
        paths: IAuthenticationPaths,
        deviceIdentifierStore: any IClientValueStore,
        identityIdentifierStore: any IClientValueStore,
        accessKeyStore: any IClientRotatingKeyStore,
        authenticationKeyStore: any IClientRotatingKeyStore,
        accessTokenStore: any IClientValueStore
    ) {
        self.hasher = hasher
        self.noncer = noncer
        self.verificationKeyStore = verificationKeyStore
        self.timestamper = timestamper
        self.network = network
        self.paths = paths
        self.deviceIdentifierStore = deviceIdentifierStore
        self.identityIdentifierStore = identityIdentifierStore
        self.accessKeyStore = accessKeyStore
        self.authenticationKeyStore = authenticationKeyStore
        self.accessTokenStore = accessTokenStore
    }

    public func identity() async throws -> String {
        try await identityIdentifierStore.get()
    }

    public func device() async throws -> String {
        try await deviceIdentifierStore.get()
    }

    private func verifyResponse(_ response: SignableMessage, _ serverIdentity: String) async throws {
        let verificationKey = try await verificationKeyStore.get(identity: serverIdentity)
        let publicKey = try await verificationKey.public()
        let verifier = verificationKey.verifier()
        try await response.verify(verifier, publicKey)
    }

    public func createAccount(_ recoveryHash: String) async throws {
        let result = try await authenticationKeyStore.initialize(recoveryHash)
        let identity = result[0]
        let publicKey = result[1]
        let rotationHash = result[2]
        let device = try await hasher.sum(publicKey)

        let nonce = try await noncer.generate128()

        let request = CreateAccountRequest(
            authentication: [
                "device": device,
                "identity": identity,
                "publicKey": publicKey,
                "recoveryHash": recoveryHash,
                "rotationHash": rotationHash,
            ],
            nonce: nonce
        )

        try await request.sign(authenticationKeyStore.signer())
        let message = try await request.serialize()
        let reply = try await network.sendRequest(paths.account.create, message)

        let response = try CreateAccountResponse.parse(reply)
        let responsePayload = response.payload as! [String: Any]
        let access = responsePayload["access"] as! [String: Any]
        try await verifyResponse(response, access["serverIdentity"] as! String)

        if access["nonce"] as! String != nonce {
            throw BetterAuthError.incorrectNonce
        }

        try await identityIdentifierStore.store(identity)
        try await deviceIdentifierStore.store(device)
    }

    public func recoverAccount(
        _ identity: String,
        _ recoveryKey: any ISigningKey,
        _ recoveryHash: String
    ) async throws {
        let result = try await authenticationKeyStore.initialize(nil)
        let current = result[1]
        let rotationHash = result[2]
        let device = try await hasher.sum(current)
        let nonce = try await noncer.generate128()

        let request = try await RecoverAccountRequest(
            request: [
                "authentication": [
                    "device": device,
                    "identity": identity,
                    "publicKey": current,
                    "recoveryHash": recoveryHash,
                    "recoveryKey": recoveryKey.public(),
                    "rotationHash": rotationHash,
                ],
            ],
            nonce: nonce
        )

        try await request.sign(recoveryKey)
        let message = try await request.serialize()
        let reply = try await network.sendRequest(paths.account.recover, message)

        let response = try RecoverAccountResponse.parse(reply)
        let responsePayload = response.payload as! [String: Any]
        let access = responsePayload["access"] as! [String: Any]
        try await verifyResponse(response, access["serverIdentity"] as! String)

        if access["nonce"] as! String != nonce {
            throw BetterAuthError.incorrectNonce
        }

        try await identityIdentifierStore.store(identity)
        try await deviceIdentifierStore.store(device)
    }

    public func generateLinkContainer(_ identity: String) async throws -> String {
        let result = try await authenticationKeyStore.initialize(nil)
        let publicKey = result[1]
        let rotationHash = result[2]
        let device = try await hasher.sum(publicKey)

        try await identityIdentifierStore.store(identity)
        try await deviceIdentifierStore.store(device)

        let linkContainer = LinkContainer(
            authentication: [
                "device": device,
                "identity": identity,
                "publicKey": publicKey,
                "rotationHash": rotationHash,
            ]
        )

        try await linkContainer.sign(authenticationKeyStore.signer())

        return try await linkContainer.serialize()
    }

    public func linkDevice(_ linkContainer: String) async throws {
        let container = try LinkContainer.parse(linkContainer)

        let result = try await authenticationKeyStore.rotate()
        let publicKey = result[0]
        let rotationHash = result[1]
        let nonce = try await noncer.generate128()

        let request = try await LinkDeviceRequest(
            authentication: [
                "device": deviceIdentifierStore.get(),
                "identity": identityIdentifierStore.get(),
                "publicKey": publicKey,
                "rotationHash": rotationHash,
            ],
            link: container.toJSON(),
            nonce: nonce
        )

        try await request.sign(authenticationKeyStore.signer())
        let message = try await request.serialize()
        let reply = try await network.sendRequest(paths.device.link, message)

        let response = try LinkDeviceResponse.parse(reply)
        let responsePayload = response.payload as! [String: Any]
        let access = responsePayload["access"] as! [String: Any]
        try await verifyResponse(response, access["serverIdentity"] as! String)

        if access["nonce"] as! String != nonce {
            throw BetterAuthError.incorrectNonce
        }
    }

    public func unlinkDevice(_ device: String) async throws {
        let nonce = try await noncer.generate128()

        let result = try await authenticationKeyStore.rotate()
        let publicKey = result[0]
        var rotationHash = result[1]

        let currentDevice = try await deviceIdentifierStore.get()
        if device == currentDevice {
            // prevent rotation if disabling this device
            rotationHash = try await hasher.sum(rotationHash)
        }

        let request = try await UnlinkDeviceRequest(
            authentication: [
                "device": currentDevice,
                "identity": identityIdentifierStore.get(),
                "publicKey": publicKey,
                "rotationHash": rotationHash,
            ],
            link: [
                "device": device,
            ],
            nonce: nonce
        )

        try await request.sign(authenticationKeyStore.signer())
        let message = try await request.serialize()
        let reply = try await network.sendRequest(paths.device.unlink, message)

        let response = try UnlinkDeviceResponse.parse(reply)
        let responsePayload = response.payload as! [String: Any]
        let access = responsePayload["access"] as! [String: Any]
        try await verifyResponse(response, access["serverIdentity"] as! String)

        if access["nonce"] as! String != nonce {
            throw BetterAuthError.incorrectNonce
        }
    }

    public func rotateDevice() async throws {
        let result = try await authenticationKeyStore.rotate()
        let publicKey = result[0]
        let rotationHash = result[1]
        let nonce = try await noncer.generate128()

        let request = try await RotateDeviceRequest(
            authentication: [
                "device": deviceIdentifierStore.get(),
                "identity": identityIdentifierStore.get(),
                "publicKey": publicKey,
                "rotationHash": rotationHash,
            ],
            nonce: nonce
        )

        try await request.sign(authenticationKeyStore.signer())
        let message = try await request.serialize()
        let reply = try await network.sendRequest(paths.device.rotate, message)

        let response = try RotateDeviceResponse.parse(reply)
        let responsePayload = response.payload as! [String: Any]
        let access = responsePayload["access"] as! [String: Any]
        try await verifyResponse(response, access["serverIdentity"] as! String)

        if access["nonce"] as! String != nonce {
            throw BetterAuthError.incorrectNonce
        }
    }

    public func createSession() async throws {
        let startNonce = try await noncer.generate128()

        let startRequest = try await RequestSessionRequest(
            access: ["nonce": startNonce],
            request: [
                "authentication": [
                    "identity": identityIdentifierStore.get(),
                ],
            ]
        )

        let startMessage = try await startRequest.serialize()
        let startReply = try await network.sendRequest(paths.session.request, startMessage)

        let startResponse = try RequestSessionResponse.parse(startReply)
        let startPayload = startResponse.payload as! [String: Any]
        let startAccess = startPayload["access"] as! [String: Any]
        try await verifyResponse(startResponse, startAccess["serverIdentity"] as! String)

        if startAccess["nonce"] as! String != startNonce {
            throw BetterAuthError.incorrectNonce
        }

        let accessResult = try await accessKeyStore.initialize(nil)
        let currentKey = accessResult[1]
        let nextKeyHash = accessResult[2]
        let finishNonce = try await noncer.generate128()

        let startResponsePayload = startResponse.payload as! [String: Any]
        let responseData = startResponsePayload["response"] as! [String: Any]
        let authData = responseData["authentication"] as! [String: Any]

        let finishRequest = try await CreateSessionRequest(
            access: [
                "publicKey": currentKey,
                "rotationHash": nextKeyHash,
            ],
            authentication: [
                "device": deviceIdentifierStore.get(),
                "nonce": authData["nonce"] as! String,
            ],
            nonce: finishNonce
        )

        try await finishRequest.sign(authenticationKeyStore.signer())
        let finishMessage = try await finishRequest.serialize()
        let finishReply = try await network.sendRequest(paths.session.create, finishMessage)

        let finishResponse = try CreateSessionResponse.parse(finishReply)
        let finishPayload = finishResponse.payload as! [String: Any]
        let finishAccess = finishPayload["access"] as! [String: Any]
        try await verifyResponse(finishResponse, finishAccess["serverIdentity"] as! String)

        if finishAccess["nonce"] as! String != finishNonce {
            throw BetterAuthError.incorrectNonce
        }

        let finishResponseData = finishPayload["response"] as! [String: Any]
        let accessInfo = finishResponseData["access"] as! [String: Any]
        try await accessTokenStore.store(accessInfo["token"] as! String)
    }

    public func refreshSession() async throws {
        let result = try await accessKeyStore.rotate()
        let publicKey = result[0]
        let rotationHash = result[1]
        let nonce = try await noncer.generate128()

        let request = try await RefreshSessionRequest(
            request: [
                "access": [
                    "publicKey": publicKey,
                    "rotationHash": rotationHash,
                    "token": accessTokenStore.get(),
                ],
            ],
            nonce: nonce
        )

        try await request.sign(accessKeyStore.signer())
        let message = try await request.serialize()
        let reply = try await network.sendRequest(paths.session.refresh, message)

        let response = try RefreshSessionResponse.parse(reply)
        let responsePayload = response.payload as! [String: Any]
        let access = responsePayload["access"] as! [String: Any]
        try await verifyResponse(response, access["serverIdentity"] as! String)

        if access["nonce"] as! String != nonce {
            throw BetterAuthError.incorrectNonce
        }

        let responseData = responsePayload["response"] as! [String: Any]
        let accessInfo = responseData["access"] as! [String: Any]
        try await accessTokenStore.store(accessInfo["token"] as! String)
    }

    public func makeAccessRequest<T>(_ path: String, _ request: T) async throws -> String {
        let accessRequest = try await AccessRequest<T>(
            access: [
                "nonce": noncer.generate128(),
                "timestamp": timestamper.format(timestamper.now()),
                "token": accessTokenStore.get(),
            ],
            request: request
        )

        try await accessRequest.sign(accessKeyStore.signer())
        let message = try await accessRequest.serialize()
        let reply = try await network.sendRequest(path, message)
        let response = try ScannableResponse.parse(reply)

        let responsePayload = response.payload as! [String: Any]
        let responseAccess = responsePayload["access"] as! [String: Any]
        let requestPayload = accessRequest.payload as! [String: Any]
        let requestAccess = requestPayload["access"] as! [String: Any]

        if responseAccess["nonce"] as! String != requestAccess["nonce"] as! String {
            throw BetterAuthError.incorrectNonce
        }

        return reply
    }
}
