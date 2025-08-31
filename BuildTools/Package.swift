// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "BuildTools",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/nicklockwood/SwiftFormat", from: "0.57.2"),
        .package(url: "https://github.com/SimplyDanny/SwiftLintPlugins", from: "0.60.0")
    ],
    targets: [.target(name: "BuildTools", path: "")]
)
