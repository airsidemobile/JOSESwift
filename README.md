![](JOSESwift.png)

<br>

**JOSESwift** is a modular and extensible framework for the [JOSE](https://datatracker.ietf.org/wg/jose/about/) standards [**JWS**](https://tools.ietf.org/html/rfc7515), [**JWE**](https://tools.ietf.org/html/rfc7516), and [**JWK**](https://tools.ietf.org/html/rfc7517) written in Swift. 
It is designed with usage on iOS and pure Swift environments in mind.

:warning: **Todo:** Mention incompleteness of standards implementation.

## Contents

- [Installation](#installation)
	- [CocoaPods](#cocoapods)
	- [Carthage](#carthage)
	- [Swift Package Manager](#swift-package-manager)
- [Usage](#usage)
	- [JWS: Digital Signatures](#jws-digital-signatures)
	- [JWE: Encryption and Decryption](#jwe-encryption-and-decryption)
	- [JWK: Representing Keys](#jwk-representing-keys)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

## Installation

### CocoaPods

To integrate JOSESwift into your Xcode project, include it in your `Podfile`:

:warning: **Todo:** Publish framework on CocoaPods and update Podfile example.

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

:warning: **Todo:** Test if this actually works.

```
github "airsidemobile/JOSESwift"
```

Then build it by running `carthage update` and drag the built framework into your Xcode project. More documentation on using Carthage can be found [here](https://github.com/Carthage/Carthage).

### Swift Package Manager

To integrate JOSESwift in your Swift project, add it as dependency in your project’s `Package.swift` file:

:warning: **Todo:** Test if this actually works and mention that non iOS crypto implementation is still to do.

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

- [JWS: Digital Signatures](#jws-digital-signatures)
	- [Securing data for transmission](#securing-data-for-transmission)
	- [Verifying data received from someone else](#verifying-received-data)
- [JWE](#jwe-encryption-and-decry): Securing data during transmission with encryption
- [JWK](#jwk-representing-keys): Representing cryptographic keys for transmission

### JWS: Digital Signatures

A JWS encapsulates and secures data using a digital signature which can be verified by the receiver of the JWS.

A JWS consists of three parts:

- Header
- Payload
- Signature

#### Securing Data for Transmission

First we create a header which specifies the algorithm we are going to use  later on to sign our data:

``` swift
let header = JWSHeader(algorithm: .RS512)
``` 

Then we specify the data we want to send:

``` swift
let message = "Do you know the way to San Jose?"

let data = message.data(using: .utf8)!

let payload = Payload(data)
```

Finally we pass our private key to a signer that will handle all the cryptographic magic for us:

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

``` swift
let key = SecKeyCreateRandomKey( /* ... */ )

let signer = Signer(signingAlgorithm: .RS512, privateKey: key)
```

Now we just put these three parts together to form our JWS:

``` swift
guard let jws = JWS(header: header, payload: payload, signer: signer) else {
    // Something went wrong!
}

// Enjoy your fresh JWS!
```

Now, you will most probably want to transmit your message, which is now digitally signed inside the JWS, to someone else. To do so, you just transmit the serialized JWS which can be obtained as follows:

``` swift
jws.compactSerializedString // ey (...) J9.RG (...) T8.T1 (...) aQ
```

The JWS compact serialization is a URL safe string that can easily be transmitted to a third party using a method of your choice.

Again, in shorter form:

``` swift
let serialization = JWS(
    header: JWSHeader(algorithm: .RS512),
    payload: Payload("Do you knwo the way to San Jose?".data(using: .utf8)!),
    signer: Signer(signingAlgorithm: .RS512, privateKey: key)
)!.compactSerializedString
```  

#### Verifying Received Data

If you receive a JWS serialization from someone else, you can easily construct a JWS from it:

``` swift
let serialization = /* ... */

let jws = try! JWS(compactSerialization: serialization)
```

You can then check it’s signature using the public key of the sender:

``` swift
guard jws.isValid(for: publicKey) else {
    // Signature is invalid!
}

// Signature is valid!
```

Now we can trust the message, which we get out of the JWS as follows:

``` swift
let data = jws.payload.data()

let message = String(data: data, encoding: .utf8)! // "Do you know the way to San Jose?"
```

Again, in shorter form:

``` swift
guard 
    let jws = try? JWS(compactSerialization: serialization),
    jws.isValid(for: publicKey),
    let message = String(data: jws.payload.data(), encoding: .utf8)
else {
    // Signature is invalid!
}
```

### JWE: Encryption and Decryption

:warning: **Todo**

### JWK: Representing Keys

:warning: **Todo**

### Nesting

:warning: **Todo**

## Contributing

Contributions to the project are encouraged and always welcome. :nerd_face:

If you want to contribute, please submit a pull request. 
For feature requests, discussions or bug reports, just open an issue.

Checkout our [contributing guidelines](.github/CONTRIBUTING.md) for a little more information.

## Credits

JOSESwift is developed and maintained by [Airside Mobile](https://www.airsidemobile.com).

:warning: **Todo:** Add main authors? Add contact addresses.

## License

JOSESwift is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.