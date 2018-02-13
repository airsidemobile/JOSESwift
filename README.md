![](JOSESwift.png)

<br>

**JOSESwift** is a modular and extensible framework for the [JOSE](https://datatracker.ietf.org/wg/jose/about/) standards [**JWS**](https://tools.ietf.org/html/rfc7515), [**JWE**](https://tools.ietf.org/html/rfc7516), and [**JWK**](https://tools.ietf.org/html/rfc7517) written in Swift. 
It is designed with usage on iOS and pure Swift environments in mind.

⚠️ **Todo:** Mention incompleteness of standards implementation.

## Contents

- [Installation](#installation)
	- [CocoaPods](#cocoapods)
	- [Carthage](#carthage)
	- [Swift Package Manager](#swift-package-manager)
- [Usage](#usage)
	- [JWS: Digital Signatures](#jws)
	- [JWE: Encryption and Decryption](#jwe)
	- [JWK: Representing Keys](#jwk)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

## Installation

### CocoaPods

To integrate JOSESwift into your Xcode project, include it in your `Podfile`:

⚠️ **Todo:** Publish framework on CocoaPods and update Podfile example.

``` ruby
source 'https://github.com/CocoaPods/Specs.git'
platform :ios, '10.0'
use_frameworks!

target '<Your Target Name>' do
    pod 'SwiftJOSE', git: 'git@github.com:airsidemobile/JOSESwift.git'
end
```

Then install it by running `pod install`. More documentation on using CocoaPods can be found [here](https://cocoapods.org).

### Carthage

To integrate JOSESwift in your Xcode project, include it in your `Cartfile`:

⚠️ **Todo:** Test if this actually works.

```
github "airsidemobile/JOSESwift"
```

Then build it by running `carthage update` and drag the built framework into your Xcode project. More documentation on using Carthage can be found [here](https://github.com/Carthage/Carthage).

### Swift Package Manager

To integrate JOSESwift in your Swift project, add it as dependency in your project’s `Package.swift` file:

⚠️ **Todo:** Test if this actually works and mention that non iOS crypto implementation is still to do.

``` Swift
import PackageDescription

let package = Package(

    /* other configuration */
    
    dependencies: [
        .package(url: "https://github.com/airsidemobile/JOSESwift.git")
    ]
)
```

Then download it using `swift package resolve`. You should now be able to use JOSESwift in your project. More documentation on using the Swift Package Manager can be found [here](https://swift.org/package-manager/).

## Usage

JOSESwift has three functional aspects:

- Securing data during transmission with digital signatures: [JWS](#jws)
- Securing data during transmission with encryption: [JWE](#jwe)
- Representing cryptographic keys for transmission: [JWK](#jwk)

### JWS: Digital Signatures

### JWE: Encryption and Decryption

### JWK: Representing Keys

### Nesting

## Contributing

## Credits

## License