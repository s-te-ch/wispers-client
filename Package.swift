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
            url: "https://github.com/s-te-ch/wispers-client/releases/download/v0.8.2/CWispersConnect.xcframework.zip",
            checksum: "1cfb88f9954bb427f3a1c34c9b72b42c8af360de4ae7699edeb98acb9709f6df"
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
