// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ssh-key-control-ui",
    defaultLocalization: "en",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "ssh-key-control-ui", targets: ["ssh-key-control-ui"])
    ],
    targets: [
        // The two deprecated calls the helper cannot do without, isolated so
        // the Swift code compiles without warnings.
        .target(
            name: "SSHKeyControlUIObjC",
            path: "Sources/SSHKeyControlUIObjC",
            publicHeadersPath: "include",
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("AppKit")]
        ),
        .target(name: "SSHKeyControlUI", dependencies: ["SSHKeyControlUIObjC"], resources: [.process("Resources")]),
        .executableTarget(name: "ssh-key-control-ui", dependencies: ["SSHKeyControlUI"]),
        .executableTarget(name: "ssh-key-control-menubar", dependencies: ["SSHKeyControlUI"]),
        .testTarget(name: "SSHKeyControlUITests", dependencies: ["SSHKeyControlUI"]),
    ]
)
