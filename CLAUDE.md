# Better Auth - Swift Implementation

## Project Context

This is a **Swift client-only implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth), a multi-repository authentication protocol.

This implementation provides **client-side only** components for iOS, macOS, watchOS, and tvOS platforms. For server functionality, use one of the server implementations (TypeScript, Python, Rust, Go, or Ruby).

## Related Repositories

**Specification:** [better-auth](https://github.com/jasoncolburne/better-auth)

**Reference Implementation:** [better-auth-ts](https://github.com/jasoncolburne/better-auth-ts) (TypeScript - Client + Server)

**Other Implementations:**
- Full (Client + Server): [Python](https://github.com/jasoncolburne/better-auth-py), [Rust](https://github.com/jasoncolburne/better-auth-rs)
- Server Only: [Go](https://github.com/jasoncolburne/better-auth-go), [Ruby](https://github.com/jasoncolburne/better-auth-rb)
- Client Only: [Dart](https://github.com/jasoncolburne/better-auth-dart), [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## Repository Structure

This repository is a **git submodule** of the parent [better-auth](https://github.com/jasoncolburne/better-auth) specification repository. The parent repository includes all 8 language implementations as submodules and provides orchestration scripts for cross-implementation testing.

### Standardized Build System

All implementations use standardized `Makefile` targets for consistency:

```bash
make setup          # Resolve dependencies (swift package resolve)
make test           # Run tests (swift test)
make lint           # Run linter (swift-format lint if installed)
make format         # Format code (swift-format format if installed)
make format-check   # Check formatting (swift-format lint if installed)
make build          # Build project (swift build)
make clean          # Clean artifacts (swift package clean)
make test-integration  # Run integration tests (swift test --filter IntegrationTests)
```

### Parent Repository Orchestration

The parent repository provides scripts in `scripts/` for running operations across all implementations:

- `scripts/run-setup.sh` - Setup all implementations
- `scripts/run-unit-tests.sh` - Run tests across all implementations
- `scripts/run-type-checks.sh` - Run type checkers across all implementations
- `scripts/run-lints.sh` - Run linters across all implementations
- `scripts/run-format-checks.sh` - Check formatting across all implementations
- `scripts/run-integration-tests.sh` - Run cross-language integration tests
- `scripts/run-all-checks.sh` - Run all checks in sequence
- `scripts/pull-repos.sh` - Update all submodules

These scripts automatically skip implementations where tooling is not available.

## Architecture

### Directory Structure

```
Sources/
└── BetterAuth/
    ├── BetterAuth.swift        # Main module file
    ├── API/                    # Client API implementation
    │   └── Client.swift        # BetterAuthClient class
    ├── Interfaces/             # Protocol definitions
    │   ├── Crypto.swift        # Hasher, Noncer, Verifier, SigningKey, VerificationKey
    │   ├── Encoding.swift      # Timestamper protocol
    │   ├── IO.swift            # Network protocol
    │   ├── Paths.swift         # AuthenticationPaths protocol
    │   └── Storage.swift       # Client storage protocols
    └── Messages/               # Protocol message types
        ├── Message.swift       # Base message types
        ├── Request.swift       # Base request types
        ├── Response.swift      # Base response types
        ├── Account.swift       # Account protocol messages
        ├── Device.swift        # Device protocol messages
        ├── Session.swift       # Session protocol messages
        └── Access.swift        # Access protocol messages

Tests/
└── BetterAuthTests/            # Swift test suite
    └── BetterAuthTests.swift
```

### Key Components

**BetterAuthClient** (`Sources/BetterAuth/API/Client.swift`)
- Implements all client-side protocol operations
- Manages authentication state and key rotation
- Handles token lifecycle
- Composes crypto, storage, and encoding protocols

**Message Types** (`Sources/BetterAuth/Messages/`)
- Swift structs conforming to `Codable`
- Type-safe request/response pairs
- JSON serialization via `JSONEncoder`/`JSONDecoder`

**Protocol Definitions** (`Sources/BetterAuth/Interfaces/`)
- Swift protocols define contracts
- Enable dependency injection
- Platform-agnostic abstractions

## Swift-Specific Patterns

### Protocol-Oriented Programming

This implementation heavily uses Swift protocols:
- `Hasher`, `Noncer`, `Verifier` for crypto operations
- `SigningKey`, `VerificationKey` for key operations
- Storage protocols for client state management
- `Network`, `Timestamper`, `AuthenticationPaths`, etc.

Protocols enable:
- Compile-time type safety
- Protocol-oriented design
- Dependency injection
- Testability with mocks

### Value Types (Structs)

All message types are defined as structs:
- Value semantics (copy-on-write)
- `Codable` conformance for JSON serialization
- Immutable by default
- Thread-safe

### Error Handling

Swift-style error handling:
- Custom error types conforming to `Error`
- Functions throw with `throws` keyword
- Error propagation with `try`
- Error handling with `do-catch`
- No exceptions - errors are values

### Codable for Serialization

All message types conform to `Codable`:
- Automatic JSON encoding/decoding
- Custom coding keys when needed
- Integration with `JSONEncoder`/`JSONDecoder`
- Type-safe serialization

### Async/Await

All async operations use Swift's native async/await:
- `async` functions
- `.await` for awaiting async calls
- `Task` for concurrent operations
- Structured concurrency

### Strong Type System

Leverages Swift's type system for safety:
- Generic types with constraints
- Associated types in protocols
- Type inference
- Compile-time safety

## Testing

### Swift Tests
Tests use Swift Testing framework or XCTest:
- Test all client protocol operations
- Mock implementations for dependencies
- Cover account, device, session, and access flows

Run with: `swift test`

### Running Tests
```bash
swift test                    # Run all tests
swift test --verbose          # Verbose output
swift test --parallel         # Parallel execution
swift test --filter BetterAuthTests  # Specific test
```

## Usage Patterns

### Client Initialization

```swift
import BetterAuth

let client = BetterAuthClient(
    crypto: CryptoConfig(
        hasher: yourHasher,
        noncer: yourNoncer,
        responsePublicKey: serverPublicKey
    ),
    encoding: EncodingConfig(
        timestamper: yourTimestamper
    ),
    io: IOConfig(
        network: yourNetwork
    ),
    paths: yourPaths,
    store: StoreConfig(
        identity: identityStore,
        device: deviceStore,
        key: KeyStoreConfig(
            authentication: authKeyStore,
            access: accessKeyStore
        ),
        token: TokenStoreConfig(
            access: tokenStore
        )
    )
)
```

### Client Operations

```swift
// Create account
try await client.createAccount(recoveryHash: recoveryHash)

// Authenticate
try await client.authenticate()

// Make access request
let response = try await client.makeAccessRequest(
    path: "/api/resource",
    payload: ["data": "value"]
)

// Rotate authentication key
try await client.rotateAuthenticationKey()

// Refresh access token
try await client.refreshAccessToken()
```

### Error Handling

```swift
do {
    try await client.authenticate()
} catch let error as BetterAuthError {
    // Handle specific error
    print("Authentication failed: \(error)")
} catch {
    // Handle generic error
    print("Unexpected error: \(error)")
}
```

## Development Workflow

### Building
```bash
swift build                   # Build the package
swift build -c release        # Release build
```

### Testing
```bash
swift test                    # Run all tests
swift test --verbose          # Verbose output
swift test --parallel         # Parallel execution
```

### Linting & Formatting
```bash
swift-format lint -r Sources/ # Lint
swift-format format -r -i Sources/  # Format in place
swiftlint                     # SwiftLint (if configured)
```

### Xcode Integration
```bash
open Package.swift            # Open in Xcode
```

## Platform Support

This Swift package supports:
- **iOS** 13.0+
- **macOS** 10.15+
- **tvOS** 13.0+
- **watchOS** 6.0+

Platform-specific considerations:
- Keychain integration for secure storage
- URLSession for networking
- CryptoKit for cryptography (iOS 13+/macOS 10.15+)

## Integration with Server Implementations

This Swift client is designed to work with any Better Auth server:
- Go server (`better-auth-go`)
- Ruby server (`better-auth-rb`)
- TypeScript server (`better-auth-ts`)
- Python server (`better-auth-py`)
- Rust server (`better-auth-rs`)

## Making Changes

When making changes to this implementation:
1. Update the code
2. Run tests: `swift test`
3. Format code: `swift-format format -r -i Sources/`
4. Build: `swift build`
5. If protocol changes: sync with the TypeScript reference implementation
6. If breaking changes: update documentation and version
7. Update this CLAUDE.md if architecture changes

## Key Files to Know

- `Sources/BetterAuth/API/Client.swift` - All client logic
- `Sources/BetterAuth/Messages/` - Protocol message definitions
- `Sources/BetterAuth/Interfaces/` - Protocol definitions
- `Tests/BetterAuthTests/BetterAuthTests.swift` - Test suite
- `Package.swift` - Swift Package Manager manifest

## Swift Package Manager

This is a Swift Package:
- `Package.swift` defines the package
- Add as dependency in other projects:
  ```swift
  dependencies: [
      .package(url: "https://github.com/jasoncolburne/better-auth-swift", from: "1.0.0")
  ]
  ```
- Import with: `import BetterAuth`

## Example Implementations

Reference implementations for protocols should use:
- **CryptoKit** for hashing and signing (iOS 13+/macOS 10.15+)
- **Security framework** for additional crypto
- **URLSession** for network operations
- **Keychain Services** for secure storage
- **UserDefaults** for non-sensitive storage

## Swift Version

Requires Swift 5.9+ for:
- Modern concurrency (async/await)
- Result builders
- Property wrappers
- Improved type system
