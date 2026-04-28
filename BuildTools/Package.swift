// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "BuildTools",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/nicklockwood/SwiftFormat", from: "0.59.1"),
        .package(url: "https://github.com/SimplyDanny/SwiftLintPlugins", from: "0.63.2")
    ],
    targets: [.target(name: "BuildTools", path: "")]
)
