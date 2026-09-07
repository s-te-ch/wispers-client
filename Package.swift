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
            url: "https://github.com/s-te-ch/wispers-client/releases/download/v0.16.0-rc1/CWispersConnect.xcframework.zip",
            checksum: "2c7b67bf3b772d5833eddc49b7d2d571ef7f18bf88602fcd256490bced9db109"
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
