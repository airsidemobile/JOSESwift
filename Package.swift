// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "JOSESwift",
    platforms: [.iOS(.v13), .macOS(.v10_15), .watchOS(.v8), .tvOS(.v15), .visionOS(.v1)],
    products: [
        .library(name: "JOSESwift", targets: ["JOSESwift"])
    ],
    dependencies: [],
    targets: [
        .target(name: "JOSESwift", path: "JOSESwift")
    ],
    swiftLanguageVersions: [.v5])
