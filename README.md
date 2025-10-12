# better-auth-swift

**Swift client-only implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth) - a multi-repository, multi-language authentication protocol.

This implementation provides client-side protocol handling for iOS, macOS, watchOS, and tvOS. For server functionality, use TypeScript, Python, Rust, Go, or Ruby implementations.

## What's Included

- ✅ **Client Only** - All client-side protocol operations
- ✅ **Protocol-Oriented** - Clean Swift protocol-based design
- ✅ **Async/Await** - Native Swift concurrency
- ✅ **Codable Messages** - Type-safe JSON serialization
- ✅ **Multi-Platform** - iOS, macOS, watchOS, tvOS support
- ✅ **Swift Package** - Distributed via Swift Package Manager

## Quick Start

This repository is a submodule of the [main spec repository](https://github.com/jasoncolburne/better-auth). For the full multi-language setup, see the parent repository.

### Setup

```bash
make setup          # swift package resolve
```

### Running Tests

```bash
make test           # Run swift test
make lint           # Run swift-format lint
make format-check   # Check code formatting
```

### Integration Testing

```bash
# Start a server (TypeScript, Python, Rust, Go, or Ruby)
# In the server repository:
make server

# In this repository, run integration tests:
make test-integration
```

## Development

This implementation uses:
- **Swift 5.9+** for modern concurrency and type system
- **Swift Package Manager** for dependency management
- **Protocol-oriented design** for interfaces
- **Codable** for JSON serialization
- **Native async/await** for concurrency

All development commands use standardized `make` targets:

```bash
make setup          # swift package resolve
make test           # swift test
make lint           # swift-format lint (if installed)
make format         # swift-format format (if installed)
make format-check   # swift-format lint (if installed)
make build          # swift build
make clean          # swift package clean
make test-integration  # Run integration tests
```

## Architecture

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation including:
- Directory structure and key components
- Swift-specific patterns (protocols, value types, error handling)
- Message types and protocol definitions
- Usage examples and API patterns

### Key Features

- **Protocol-Oriented Programming**: Hasher, Noncer, Verifier, SigningKey, VerificationKey protocols
- **Value Types (Structs)**: All messages are immutable structs with value semantics
- **Error Handling**: Swift-style error handling with custom error types
- **Codable for Serialization**: Automatic JSON encoding/decoding
- **Async/Await**: Native Swift concurrency for all async operations

### Platform Support

- **iOS** 13.0+
- **macOS** 10.15+
- **tvOS** 13.0+
- **watchOS** 6.0+

### Reference Implementations

Reference implementations should use:
- **CryptoKit** for hashing and signing (iOS 13+/macOS 10.15+)
- **URLSession** for network operations
- **Keychain Services** for secure storage
- **UserDefaults** for non-sensitive storage

## Integration with Server Implementations

This Swift client is designed to work with any Better Auth server:
- **TypeScript server** (better-auth-ts)
- **Python server** (better-auth-py)
- **Rust server** (better-auth-rs)
- **Go server** (better-auth-go)
- **Ruby server** (better-auth-rb)

## Related Implementations

**Full Implementations (Client + Server):**
- [TypeScript](https://github.com/jasoncolburne/better-auth-ts) - Reference implementation
- [Python](https://github.com/jasoncolburne/better-auth-py)
- [Rust](https://github.com/jasoncolburne/better-auth-rs)

**Server-Only:**
- [Go](https://github.com/jasoncolburne/better-auth-go)
- [Ruby](https://github.com/jasoncolburne/better-auth-rb)

**Client-Only:**
- [Swift](https://github.com/jasoncolburne/better-auth-swift) - **This repository**
- [Dart](https://github.com/jasoncolburne/better-auth-dart)
- [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## License

MIT
