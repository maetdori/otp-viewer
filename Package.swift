// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "OTPBar",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "OTPBar", path: "Sources/OTPBar")
    ]
)
