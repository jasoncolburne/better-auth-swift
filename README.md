# better-auth-swift

A Swift port of the better-auth authentication client.

## Overview

This is a pure-logic port of the better-auth client from TypeScript to Swift. The library provides a secure authentication client with support for:

- Account creation and recovery
- Device linking
- Key rotation
- Access token management
- Authenticated requests

## Project Structure

```
Sources/BetterAuth/
├── API/                    # Client API
│   └── Client.swift        # Main BetterAuthClient class
├── Interfaces/            # Protocol definitions
│   ├── Crypto.swift       # Cryptographic interfaces
│   ├── Encoding.swift     # Encoding interfaces
│   ├── IO.swift          # Network interfaces
│   ├── Paths.swift       # Path configuration
│   └── Storage.swift     # Storage interfaces
└── Messages/             # Message classes
    ├── Message.swift     # Base message classes
    ├── Request.swift     # Client request classes
    ├── Response.swift    # Server response classes
    └── ...              # Various message types

Tests/BetterAuthTests/
├── Implementation/       # Test implementations
│   ├── Crypto/          # Crypto implementations (secp256r1, hash, nonce)
│   ├── Encoding/        # Encoding implementations (base64, timestamper)
│   └── Storage/         # Storage implementations (client stores)
└── Integration/         # Integration tests
    └── IntegrationTests.swift
```

## Dependencies

All dependencies are test dependencies since this is pure protocol logic:

- `BLAKE3` (nixberg/blake3-swift) - BLAKE3 hashing for tests
- `Crypto` (apple/swift-crypto) - Cryptographic primitives for tests

## Platform Requirements

- macOS 13.0+ / iOS 16.0+
- Swift 6.0+

## Running Tests

To run the integration tests (requires a running better-auth server on localhost:8080):

```bash
swift test
```

## Usage

See `Tests/BetterAuthTests/Integration/IntegrationTests.swift` for complete examples of how to instantiate and use the client.

### Basic Example

```swift
import BetterAuth

// Set up the client with required dependencies
let client = BetterAuthClient(
    hasher: hasher,
    noncer: noncer,
    responsePublicKey: responseVerificationKey,
    timestamper: timestamper,
    network: network,
    paths: authenticationPaths,
    deviceIdentifierStore: deviceIdentifierStore,
    identityIdentifierStore: identityIdentifierStore,
    accessKeyStore: accessKeyStore,
    authenticationKeyStore: authenticationKeyStore,
    accessTokenStore: accessTokenStore
)

// Create an account
try await client.createAccount(recoveryHash)

// Authenticate
try await client.authenticate()

// Make authenticated requests
let reply = try await client.makeAccessRequest("/api/endpoint", requestData)
```

## API

### BetterAuthClient

The main client class provides the following methods:

- `identity()` - Get the current identity identifier
- `device()` - Get the current device identifier
- `createAccount(_:)` - Create a new account with a recovery hash
- `generateLinkContainer(_:)` - Generate a link container for device linking
- `linkDevice(_:)` - Link a new device using a link container
- `rotateAuthenticationKey()` - Rotate the authentication key pair
- `authenticate()` - Perform two-phase authentication
- `refreshAccessToken()` - Refresh the access token with key rotation
- `recoverAccount(_:_:)` - Recover an account using the recovery key
- `makeAccessRequest(_:_:)` - Make an authenticated API request

## License

See LICENSE file for details.
