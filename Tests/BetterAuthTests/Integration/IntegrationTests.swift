import OrderedCollections
import XCTest

@testable import BetterAuth

let debugLogging = false

class Secp256r1VerificationKey: IVerificationKey {
    let publicKey: String
    let secpVerifier: Secp256r1Verifier

    init(_ publicKey: String) {
        self.publicKey = publicKey
        secpVerifier = Secp256r1Verifier()
    }

    func `public`() async throws -> String {
        publicKey
    }

    func verifier() -> any IVerifier {
        secpVerifier
    }

    func verify(_ message: String, _ signature: String) async throws {
        try await secpVerifier.verify(message, signature, publicKey)
    }
}

let authenticationPaths = IAuthenticationPaths(
    account: AccountPaths(
        create: "/account/create",
        recover: "/account/recover",
        delete: "/account/delete"
    ),
    session: SessionPaths(
        request: "/session/request",
        create: "/session/create",
        refresh: "/session/refresh"
    ),
    device: DevicePaths(
        rotate: "/device/rotate",
        link: "/device/link",
        unlink: "/device/unlink"
    )
)

class Network: INetwork {
    func sendRequest(_ path: String, _ message: String) async throws -> String {
        if debugLogging {
            print(message)
        }

        var request = URLRequest(url: URL(string: "http://localhost:8080\(path)")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = message.data(using: .utf8)

        let (data, _) = try await URLSession.shared.data(for: request)
        let reply = String(data: data, encoding: .utf8)!

        if debugLogging {
            print(reply)
        }

        return reply
    }
}

class FakeResponse: ServerResponse<[String: Any]> {
    static func parse(_ message: String) throws -> FakeResponse {
        try ServerResponse<[String: Any]>.parse(message) { response, serverIdentity, nonce in
            FakeResponse(response: response, serverIdentity: serverIdentity, nonce: nonce)
        } as! FakeResponse
    }
}

func executeFlow(
    _ betterAuthClient: BetterAuthClient,
    _ eccVerifier: any IVerifier,
    _ responseVerificationKey: any IVerificationKey
) async throws {
    try await betterAuthClient.rotateDevice()
    try await betterAuthClient.createSession()
    try await betterAuthClient.refreshSession()

    try await testAccess(betterAuthClient, eccVerifier, responseVerificationKey)
}

func testAccess(
    _ betterAuthClient: BetterAuthClient,
    _ eccVerifier: any IVerifier,
    _ responseVerificationKey: any IVerificationKey
) async throws {
    let message: OrderedDictionary<String, String> = [
        "foo": "bar",
        "bar": "foo",
    ]
    let reply = try await betterAuthClient.makeAccessRequest("/foo/bar", message)
    let response = try FakeResponse.parse(reply)

    try await response.verify(eccVerifier, responseVerificationKey.public())

    let responsePayload = response.payload as! [String: Any]
    let responseData = responsePayload["response"] as! [String: Any]
    if responseData["wasFoo"] as! String != "bar" || responseData["wasBar"] as! String != "foo" {
        throw BetterAuthError.invalidData
    }
}

final class IntegrationTests: XCTestCase {
    func testCompletesAuthFlows() async throws {
        let eccVerifier = Secp256r1Verifier()
        let hasher = Hasher()
        let noncer = Noncer()

        let recoverySigner = Secp256r1()
        await recoverySigner.generate()

        let network = Network()

        let responsePublicKey = try await network.sendRequest("/key/response", "")
        let responseVerificationKey = Secp256r1VerificationKey(responsePublicKey)

        let betterAuthClient = BetterAuthClient(
            hasher: hasher,
            noncer: noncer,
            verificationKeyStore: VerificationKeyStore(responseVerificationKey),
            timestamper: Rfc3339Nano(),
            network: network,
            paths: authenticationPaths,
            deviceIdentifierStore: ClientValueStore(),
            identityIdentifierStore: ClientValueStore(),
            accessKeyStore: ClientRotatingKeyStore(),
            authenticationKeyStore: ClientRotatingKeyStore(),
            accessTokenStore: ClientValueStore()
        )

        let recoveryHash = try await hasher.sum(recoverySigner.public())
        try await betterAuthClient.createAccount(recoveryHash)
        try await executeFlow(betterAuthClient, eccVerifier, responseVerificationKey)
    }

    func testRecoversFromLoss() async throws {
        let eccVerifier = Secp256r1Verifier()
        let hasher = Hasher()
        let noncer = Noncer()

        let recoverySigner = Secp256r1()
        await recoverySigner.generate()

        let network = Network()

        let responsePublicKey = try await network.sendRequest("/key/response", "")
        let responseVerificationKey = Secp256r1VerificationKey(responsePublicKey)

        let betterAuthClient = BetterAuthClient(
            hasher: hasher,
            noncer: noncer,
            verificationKeyStore: VerificationKeyStore(responseVerificationKey),
            timestamper: Rfc3339Nano(),
            network: network,
            paths: authenticationPaths,
            deviceIdentifierStore: ClientValueStore(),
            identityIdentifierStore: ClientValueStore(),
            accessKeyStore: ClientRotatingKeyStore(),
            authenticationKeyStore: ClientRotatingKeyStore(),
            accessTokenStore: ClientValueStore()
        )

        let recoveredBetterAuthClient = BetterAuthClient(
            hasher: Hasher(),
            noncer: Noncer(),
            verificationKeyStore: VerificationKeyStore(responseVerificationKey),
            timestamper: Rfc3339Nano(),
            network: network,
            paths: authenticationPaths,
            deviceIdentifierStore: ClientValueStore(),
            identityIdentifierStore: ClientValueStore(),
            accessKeyStore: ClientRotatingKeyStore(),
            authenticationKeyStore: ClientRotatingKeyStore(),
            accessTokenStore: ClientValueStore()
        )

        let recoveryHash = try await hasher.sum(recoverySigner.public())
        try await betterAuthClient.createAccount(recoveryHash)
        let identity = try await betterAuthClient.identity()
        let nextRecoverySigner = Secp256r1()
        await nextRecoverySigner.generate()
        let nextRecoverySignerPublicKey = try await nextRecoverySigner.public()
        let nextRecoveryHash = try await hasher.sum(nextRecoverySignerPublicKey)

        try await recoveredBetterAuthClient.recoverAccount(identity, recoverySigner, nextRecoveryHash)
        try await executeFlow(recoveredBetterAuthClient, eccVerifier, responseVerificationKey)
    }

    func testLinksAnotherDevice() async throws {
        let eccVerifier = Secp256r1Verifier()
        let hasher = Hasher()
        let noncer = Noncer()

        let recoverySigner = Secp256r1()
        await recoverySigner.generate()

        let network = Network()

        let responsePublicKey = try await network.sendRequest("/key/response", "")
        let responseVerificationKey = Secp256r1VerificationKey(responsePublicKey)

        let betterAuthClient = BetterAuthClient(
            hasher: hasher,
            noncer: noncer,
            verificationKeyStore: VerificationKeyStore(responseVerificationKey),
            timestamper: Rfc3339Nano(),
            network: network,
            paths: authenticationPaths,
            deviceIdentifierStore: ClientValueStore(),
            identityIdentifierStore: ClientValueStore(),
            accessKeyStore: ClientRotatingKeyStore(),
            authenticationKeyStore: ClientRotatingKeyStore(),
            accessTokenStore: ClientValueStore()
        )

        let linkedBetterAuthClient = BetterAuthClient(
            hasher: Hasher(),
            noncer: Noncer(),
            verificationKeyStore: VerificationKeyStore(responseVerificationKey),
            timestamper: Rfc3339Nano(),
            network: network,
            paths: authenticationPaths,
            deviceIdentifierStore: ClientValueStore(),
            identityIdentifierStore: ClientValueStore(),
            accessKeyStore: ClientRotatingKeyStore(),
            authenticationKeyStore: ClientRotatingKeyStore(),
            accessTokenStore: ClientValueStore()
        )

        let recoveryHash = try await hasher.sum(recoverySigner.public())
        try await betterAuthClient.createAccount(recoveryHash)
        let identity = try await betterAuthClient.identity()

        // get link container from the new device
        let linkContainer = try await linkedBetterAuthClient.generateLinkContainer(identity)
        if debugLogging {
            print(linkContainer)
        }

        // submit an endorsed link container with existing device
        try await betterAuthClient.linkDevice(linkContainer)
        try await executeFlow(linkedBetterAuthClient, eccVerifier, responseVerificationKey)
        try await linkedBetterAuthClient.unlinkDevice(betterAuthClient.device())
    }

    func testDetectsMismatchedAccessNonce() async throws {
        let hasher = Hasher()
        let noncer = Noncer()

        let recoverySigner = Secp256r1()
        await recoverySigner.generate()

        let network = Network()

        let responsePublicKey = try await network.sendRequest("/key/response", "")
        let responseVerificationKey = Secp256r1VerificationKey(responsePublicKey)

        let accessTokenStore = ClientValueStore()
        let betterAuthClient = BetterAuthClient(
            hasher: hasher,
            noncer: noncer,
            verificationKeyStore: VerificationKeyStore(responseVerificationKey),
            timestamper: Rfc3339Nano(),
            network: network,
            paths: authenticationPaths,
            deviceIdentifierStore: ClientValueStore(),
            identityIdentifierStore: ClientValueStore(),
            accessKeyStore: ClientRotatingKeyStore(),
            authenticationKeyStore: ClientRotatingKeyStore(),
            accessTokenStore: accessTokenStore
        )

        let recoveryHash = try await hasher.sum(recoverySigner.public())
        try await betterAuthClient.createAccount(recoveryHash)

        do {
            try await betterAuthClient.createSession()
            let message: OrderedDictionary<String, String> = [
                "foo": "bar",
                "bar": "foo",
            ]
            _ = try await betterAuthClient.makeAccessRequest("/bad/nonce", message)

            XCTFail("expected a failure")
        } catch BetterAuthError.incorrectNonce {
            // Expected
        }
    }
}
