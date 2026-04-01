// swift-tools-version: 5.9
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
            path: "CWispersConnect.xcframework"
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
