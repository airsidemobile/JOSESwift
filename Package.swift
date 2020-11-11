// swift-tools-version:5.2
import PackageDescription

let package = Package(
    name: "JOSESwift",
    platforms: [.iOS(.v10), .macOS(.v10_15)],
    products: [
        .library(name: "JOSESwift", targets: ["JOSESwift"])
    ],
    dependencies: [],
    targets: [
        .target(name: "JOSESwift", path: "JOSESwift")
    ],
    swiftLanguageVersions: [.v5])
