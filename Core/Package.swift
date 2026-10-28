// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SoftEtherCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "SoftEtherCore", targets: ["SoftEtherCore"])],
    targets: [
        .target(name: "SoftEtherCore"),
        .testTarget(name: "SoftEtherCoreTests", dependencies: ["SoftEtherCore"]),
    ],
    swiftLanguageVersions: [.v5]
)
