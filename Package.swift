// swift-tools-version: 5.9
//
// Root-level Package.swift for SPM consumers who add this repo as a dependency
// via URL. SPM requires Package.swift at the repo root — it can't resolve
// manifests in subdirectories. The Swift wrapper source lives in
// wrappers/swift/Sources/; the prebuilt xcframework is downloaded from GitHub
// Releases.
//
// See also: wrappers/swift/Package.swift (used by the Files iOS app and local
// Xcode development with a pre-built xcframework on disk).

import PackageDescription

let package = Package(
    name: "WispersConnect",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "WispersConnect", targets: ["WispersConnect"]),
    ],
    targets: [
        .binaryTarget(
            name: "CWispersConnect",
            url: "https://github.com/s-te-ch/wispers-client/releases/download/v0.14.1/CWispersConnect.xcframework.zip",
            checksum: "42a665ee6a55052fcb45117ea2c42ac8d1671f66f20a6354700d1c7f267fc2e5"
        ),
        .target(
            name: "WispersConnect",
            dependencies: ["CWispersConnect"],
            path: "wrappers/swift/Sources/WispersConnect",
            linkerSettings: [
                .linkedLibrary("c++"),
                .linkedLibrary("iconv"),
                .linkedLibrary("resolv"),
            ]
        ),
    ]
)
