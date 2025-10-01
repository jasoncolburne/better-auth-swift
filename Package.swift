// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "BetterAuth",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "BetterAuth",
            targets: ["BetterAuth"]),
    ],
    dependencies: [
        .package(url: "https://github.com/nixberg/blake3-swift.git", from: "0.1.2"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "BetterAuth"),
        .testTarget(
            name: "BetterAuthTests",
            dependencies: [
                "BetterAuth",
                .product(name: "BLAKE3", package: "blake3-swift"),
                .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
    ]
)
