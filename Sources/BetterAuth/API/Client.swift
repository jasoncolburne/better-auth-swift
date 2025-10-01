import Foundation

public class BetterAuthClient {
  private let hasher: any IHasher
  private let noncer: any INoncer
  private let responsePublicKey: any IVerificationKey
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
    responsePublicKey: any IVerificationKey,
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
    self.responsePublicKey = responsePublicKey
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
    return try await identityIdentifierStore.get()
  }

  public func device() async throws -> String {
    return try await deviceIdentifierStore.get()
  }

  private func verifyResponse(_ response: SignableMessage, _ publicKeyHash: String) async throws {
    let publicKey = try await responsePublicKey.public()
    let hash = try await hasher.sum(publicKey)

    if hash != publicKeyHash {
      throw BetterAuthError.hashMismatch
    }

    let verifier = responsePublicKey.verifier()
    try await response.verify(verifier, publicKey)
  }

  public func createAccount(_ recoveryHash: String) async throws {
    let result = try await authenticationKeyStore.initialize(recoveryHash)
    let identity = result[0]
    let publicKey = result[1]
    let rotationHash = result[2]
    let device = try await hasher.sum(publicKey)

    let nonce = try await noncer.generate128()

    let request = CreationRequest(
      authentication: [
        "device": device,
        "identity": identity,
        "publicKey": publicKey,
        "recoveryHash": recoveryHash,
        "rotationHash": rotationHash,
      ],
      nonce: nonce
    )

    try await request.sign(try await authenticationKeyStore.signer())
    let message = try await request.serialize()
    let reply = try await network.sendRequest(paths.register.create, message)

    let response = try CreationResponse.parse(reply)
    let responsePayload = response.payload as! [String: Any]
    let access = responsePayload["access"] as! [String: Any]
    try await verifyResponse(response, access["responseKeyHash"] as! String)

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

    try await linkContainer.sign(try await authenticationKeyStore.signer())

    return try await linkContainer.serialize()
  }

  public func linkDevice(_ linkContainer: String) async throws {
    let container = try LinkContainer.parse(linkContainer)
    let nonce = try await noncer.generate128()

    let request = LinkDeviceRequest(
      authentication: [
        "device": try await deviceIdentifierStore.get(),
        "identity": try await identityIdentifierStore.get(),
      ],
      link: container.toJSON(),
      nonce: nonce
    )

    try await request.sign(try await authenticationKeyStore.signer())
    let message = try await request.serialize()
    let reply = try await network.sendRequest(paths.register.link, message)

    let response = try LinkDeviceResponse.parse(reply)
    let responsePayload = response.payload as! [String: Any]
    let access = responsePayload["access"] as! [String: Any]
    try await verifyResponse(response, access["responseKeyHash"] as! String)

    if access["nonce"] as! String != nonce {
      throw BetterAuthError.incorrectNonce
    }
  }

  public func rotateAuthenticationKey() async throws {
    let result = try await authenticationKeyStore.rotate()
    let publicKey = result[0]
    let rotationHash = result[1]
    let nonce = try await noncer.generate128()

    let request = RotateAuthenticationKeyRequest(
      authentication: [
        "device": try await deviceIdentifierStore.get(),
        "identity": try await identityIdentifierStore.get(),
        "publicKey": publicKey,
        "rotationHash": rotationHash,
      ],
      nonce: nonce
    )

    try await request.sign(try await authenticationKeyStore.signer())
    let message = try await request.serialize()
    let reply = try await network.sendRequest(paths.rotate.authentication, message)

    let response = try RotateAuthenticationKeyResponse.parse(reply)
    let responsePayload = response.payload as! [String: Any]
    let access = responsePayload["access"] as! [String: Any]
    try await verifyResponse(response, access["responseKeyHash"] as! String)

    if access["nonce"] as! String != nonce {
      throw BetterAuthError.incorrectNonce
    }
  }

  public func authenticate() async throws {
    let startNonce = try await noncer.generate128()

    let startRequest = StartAuthenticationRequest(
      access: ["nonce": startNonce],
      request: [
        "authentication": [
          "identity": try await identityIdentifierStore.get()
        ]
      ]
    )

    let startMessage = try await startRequest.serialize()
    let startReply = try await network.sendRequest(paths.authenticate.start, startMessage)

    let startResponse = try StartAuthenticationResponse.parse(startReply)
    let startPayload = startResponse.payload as! [String: Any]
    let startAccess = startPayload["access"] as! [String: Any]
    try await verifyResponse(startResponse, startAccess["responseKeyHash"] as! String)

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

    let finishRequest = FinishAuthenticationRequest(
      access: [
        "publicKey": currentKey,
        "rotationHash": nextKeyHash,
      ],
      authentication: [
        "device": try await deviceIdentifierStore.get(),
        "nonce": authData["nonce"] as! String,
      ],
      nonce: finishNonce
    )

    try await finishRequest.sign(try await authenticationKeyStore.signer())
    let finishMessage = try await finishRequest.serialize()
    let finishReply = try await network.sendRequest(paths.authenticate.finish, finishMessage)

    let finishResponse = try FinishAuthenticationResponse.parse(finishReply)
    let finishPayload = finishResponse.payload as! [String: Any]
    let finishAccess = finishPayload["access"] as! [String: Any]
    try await verifyResponse(finishResponse, finishAccess["responseKeyHash"] as! String)

    if finishAccess["nonce"] as! String != finishNonce {
      throw BetterAuthError.incorrectNonce
    }

    let finishResponseData = finishPayload["response"] as! [String: Any]
    let accessInfo = finishResponseData["access"] as! [String: Any]
    try await accessTokenStore.store(accessInfo["token"] as! String)
  }

  public func refreshAccessToken() async throws {
    let result = try await accessKeyStore.rotate()
    let publicKey = result[0]
    let rotationHash = result[1]
    let nonce = try await noncer.generate128()

    let request = RefreshAccessTokenRequest(
      request: [
        "access": [
          "publicKey": publicKey,
          "rotationHash": rotationHash,
          "token": try await accessTokenStore.get(),
        ]
      ],
      nonce: nonce
    )

    try await request.sign(try await accessKeyStore.signer())
    let message = try await request.serialize()
    let reply = try await network.sendRequest(paths.rotate.access, message)

    let response = try RefreshAccessTokenResponse.parse(reply)
    let responsePayload = response.payload as! [String: Any]
    let access = responsePayload["access"] as! [String: Any]
    try await verifyResponse(response, access["responseKeyHash"] as! String)

    if access["nonce"] as! String != nonce {
      throw BetterAuthError.incorrectNonce
    }

    let responseData = responsePayload["response"] as! [String: Any]
    let accessInfo = responseData["access"] as! [String: Any]
    try await accessTokenStore.store(accessInfo["token"] as! String)
  }

  public func recoverAccount(_ identity: String, _ recoveryKey: any ISigningKey) async throws {
    let result = try await authenticationKeyStore.initialize(nil)
    let current = result[1]
    let rotationHash = result[2]
    let device = try await hasher.sum(current)
    let nonce = try await noncer.generate128()

    let request = RecoverAccountRequest(
      request: [
        "authentication": [
          "device": device,
          "identity": identity,
          "publicKey": current,
          "recoveryKey": try await recoveryKey.public(),
          "rotationHash": rotationHash,
        ]
      ],
      nonce: nonce
    )

    try await request.sign(recoveryKey)
    let message = try await request.serialize()
    let reply = try await network.sendRequest(paths.register.recover, message)

    let response = try RecoverAccountResponse.parse(reply)
    let responsePayload = response.payload as! [String: Any]
    let access = responsePayload["access"] as! [String: Any]
    try await verifyResponse(response, access["responseKeyHash"] as! String)

    if access["nonce"] as! String != nonce {
      throw BetterAuthError.incorrectNonce
    }

    try await identityIdentifierStore.store(identity)
    try await deviceIdentifierStore.store(device)
  }

  public func makeAccessRequest<T>(_ path: String, _ request: T) async throws -> String {
    let accessRequest = AccessRequest<T>(
      access: [
        "nonce": try await noncer.generate128(),
        "timestamp": timestamper.format(timestamper.now()),
        "token": try await accessTokenStore.get(),
      ],
      request: request
    )

    try await accessRequest.sign(try await accessKeyStore.signer())
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
