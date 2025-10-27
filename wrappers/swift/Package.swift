// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "Slauth",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "Slauth",
            targets: ["Slauth"]
        )
    ],
    targets: [
        .systemLibrary(
            name: "SlauthFFI",
            path: "ffi"
        ),
        .binaryTarget(
            name: "libslauth",
            path: "libslauth.xcframework"
        ),
        .target(
            name: "Slauth",
            dependencies: [
                "SlauthFFI",
                "libslauth"
            ],
            path: "classes"
        )
    ]
)
