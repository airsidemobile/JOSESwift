// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "BuildTools",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/nicklockwood/SwiftFormat", from: "0.58.1"),
        .package(url: "https://github.com/SimplyDanny/SwiftLintPlugins", from: "0.61.0")
    ],
    targets: [.target(name: "BuildTools", path: "")]
)
