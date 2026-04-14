// swift-tools-version: 5.9
//
// Local Package.swift for use by the Files iOS app and Xcode development.
// References the xcframework built on disk (via scripts/build-xcframework.sh),
// not a remote download.
//
// For SPM consumers adding this repo as a remote dependency, the root-level
// Package.swift is used instead (SPM requires the manifest at the repo root).

import PackageDescription

let package = Package(
    name: "WispersConnect",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "WispersConnect", targets: ["WispersConnect"]),
    ],
    targets: [
        .binaryTarget(
            name: "CWispersConnect",
            url: "https://github.com/s-te-ch/wispers-client/releases/download/v0.8.0-rc1/CWispersConnect.xcframework.zip",
            checksum: "a5a9d50111c4e0b27c3a890b2264a9bcc4a79434f9ba569c10c58fe325e13df1"
        ),
        .target(
            name: "WispersConnect",
            dependencies: ["CWispersConnect"],
            path: "Sources/WispersConnect",
            linkerSettings: [
                .linkedLibrary("c++"),
                .linkedLibrary("iconv"),
                .linkedLibrary("resolv"),
            ]
        ),
    ]
)
