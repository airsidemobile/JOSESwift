// swift-tools-version:4.2
import PackageDescription

let package = Package(
    name: "JOSESwift",
    dependencies: [
      .package(url: "https://github.com/danger/swift.git", from: "1.4.0")
    ],
    targets: [
        // This is just an arbitrary Swift file in our app, that has
        // no dependencies outside of Foundation, the dependencies section
        // ensures that the library for Danger gets build also.
        // See https://danger.systems/swift/guides/getting_started.html
        .target(name: "JOSESwift", dependencies: ["Danger"], path: ".", sources: ["Empty.swift"]),
    ]
)
