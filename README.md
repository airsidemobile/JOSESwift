![JOSESwift](logo/JOSESwift-full.svg)

<br>

**JOSESwift** (WIP) is a modular and extensible framework for the [JOSE](https://datatracker.ietf.org/wg/jose/about/) standards [**JWS**](https://tools.ietf.org/html/rfc7515), [**JWE**](https://tools.ietf.org/html/rfc7516), and [**JWK**](https://tools.ietf.org/html/rfc7517) written in Swift. 
It is designed with usage on iOS and pure Swift environments in mind.

As of now, usage is limited to iOS. See [Security](#security) for details.

> :bulb: Please note that this implementation of the JOSE standards is not fully complete yet. For example, there is only a limited set of supported algorithms available at the moment. Moreover we currently only support compact serialization of JOSE types. If you are missing a specific feature, algorithm, or serialization, feel free to [submit a pull request](#contributing).

## Contents

- [Features](#features)
- [Installation](#installation)
	- [CocoaPods](#cocoapods)
	- [Carthage](#carthage)
	- [Swift Package Manager](#swift-package-manager)
- [Usage](#usage)
	- [JWS: Digital Signatures](#jws-digital-signatures)
	- [JWE: Encryption and Decryption](#jwe-encryption-and-decryption)
	- [JWK: Representing Keys](#jwk-representing-keys)
- [Security](#security)
- [Contributing](#contributing)
- [Resources](#resources)
- [Credits](#credits)
- [License](#license)

## Features

If you are missing a specific feature, algorithm or serialization, feel free to [submit a pull request](#contributing).

### General

*Supported serializations:*

| Compact Serialization | JSON Serialization |
| :-------------------: | :----------------: |
| :white_check_mark:    |                    |

### JWS :pencil:

Digitally signing and verifying arbitrary data using the JWS standard.

*Supported algorithms:*

| HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | ES384 | ES512 | PS256  | PS384 | PS512 |
| :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
|  | |  | | | | :white_check_mark: | | | | | |

### JWE :lock:

Encrypting and decrypting arbitrary data using the JWE standard.

*Supported key encryption algorithms:*

| RSA1_5 | RSA-OAEP | RSA-OAEP-256 | A128KW | A192KW | A256KW | dir | ECDH-ES | ECDH-ES+A128KW | ECDH-ES+A192KW | ECDH-ES+A256KW | A128GCMKW | A192GCMKW | A256GCMKW | PBES2-HS256+A128KW | PBES2-HS384+A192KW | PBES2-HS512+A256KW |
| :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | 
| :white_check_mark: | | | | | | | | | | | | | | | | |

*Supported content encryption algorithms:*

| A128CBC-HS256 | A192CBC-HS384 | A256CBC-HS512 | A128GCM | A192GCM | A256GCM |
| :--: | :--: | :--: | :--: | :--: | :--: |
| | | :white_check_mark: | | | |

### JWK :key:

Encoding and decoding RSA public key data in PKCS#1 format as well as iOS `SecKey`s.

*Supported key types:*

| EC | RSA | oct |
| :--: | :--: | :--: |
| | :white_check_mark: | |

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

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

To integrate JOSESwift in your Swift project, add it as dependency in your `Package.swift` file:

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

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

JOSESwift covers three functional aspects:

1. [JWS: Digital Signatures](#jws-digital-signatures)
	- [Signing data for transmission](#signing-data-for-transmission)
	- [Verifying received data](#verifying-received-data)
2. [JWE: Encryption and Decryption](#jwe-encryption-and-decryption)
	- [Encrypting data for transmission](#encrypting-data-for-transmission)
	- [Decrypting received data](#decrypting-received-data)
3. [JWK: Representing Keys](#jwk-representing-keys)
	- [Encoding RSA Public Keys](#encoding-rsa-public-keys)
	- [Decoding RSA Public Keys](#decoding-rsa-public-keys)

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

### JWS: Digital Signatures

A JWS encapsulates and secures data using a digital signature which can be verified by the receiver of the JWS.

A JWS consists of three parts:

1. Header
2. Payload
3. Signature

#### Signing Data for Transmission

In short:

``` swift
let privateKey: SecKey = /* ... */

let message = "Summer ⛱, Sun ☀️, Cactus 🌵"

let jws = try! JWS(
    header: JWSHeader(algorithm: .RS512),
    payload: Payload(message.data(using: .utf8)!),
    signer: Signer(signingAlgorithm: .RS512, privateKey: privateKey)!
)

print(jws.compactSerializedString) // ey (...) J9.U3 (...) LU.na (...) 1A
```  

<details>

<summary>
Click here for a more detailed description of creating a JWS to sign data.
</summary>

<br>

First, we create a header which specifies the algorithm we are going to use  later on to sign our data:

``` swift
let header = JWSHeader(algorithm: .RS512)
``` 

Then we specify the data we want to send:

``` swift
let message = "Summer ⛱, Sun ☀️, Cactus 🌵"

let data = message.data(using: .utf8)!

let payload = Payload(data)
```

Finally, we pass our private key to a signer that will handle all the cryptographic magic for us:

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

``` swift
let privateKey: SecKey = /* ... */

let signer = Signer(signingAlgorithm: .RS512, privateKey: privateKey)!
```

Now we just put these three parts together to form our JWS:

``` swift
guard let jws = try? JWS(header: header, payload: payload, signer: signer) else {
    // Something went wrong!
}

// Enjoy your fresh JWS!
```

Now, you will most probably want to transmit your message, which is now digitally signed inside the JWS, to someone else. To do so, you just transmit the serialized JWS which can be obtained as follows:

``` swift
print(jws.compactSerializedString) // ey (...) J9.U3 (...) LU.na (...) 1A
```

The JWS compact serialization is a URL safe string that can easily be transmitted to a third party using a method of your choice.

</details>

#### Verifying Received Data

In short:

``` swift
let publicKey: SecKey = /* ... */

let serialization = /* ... */

do {
    let jws = try JWS(compactSerialization: serialization)
    let payload = try jws.validate(with: publicKey).payload
    let message = String(data: payload.data(), encoding: .utf8)!

    print(message) // Summer ⛱, Sun ☀️, Cactus 🌵
}
```

<details>

<summary>
Click here for a more detailed description of verifying a serialized JWS and retrieving its payload.
</summary>

<br>

If you receive a JWS serialization from someone else, you can easily construct a JWS from it:

``` swift
let serialization = /* ... */

do {
    let jws = try JWS(compactSerialization: serialization)
} catch {
    // Deserialization failed!
}
```

You can then check its signature using the public key of the sender:

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

``` swift
let publicKey: SecKey = /* ... */

guard jws.isValid(for: publicKey) else {
    // Something went wrong!
}

// or

do {
    _ = try jws.validate(with: publicKey)
} catch {
    // Something went wrong
}

// Everything ok!
```

Now we can trust the message, which we get from the JWS as follows:

``` swift
let data = jws.payload.data()

let message = String(data: data, encoding: .utf8)! // Summer ⛱, Sun ☀️, Cactus 🌵
```

</details>

### JWE: Encryption and Decryption

A JWE encapsulates and secures data by encrypting it. It can be decrypted by the receiver of the JWE.

In order to construct a JWE we need to provide the following parts:

1. Header
2. Plaintext
3. Encrypter

#### Encrypting Data for Transmission

In short:

``` swift
let publicKey: SecKey = /* ... */

let message = "Summer ⛱, Sun ☀️, Cactus 🌵"

let jwe = try! JWE(
    header: JWEHeader(algorithm: .RSA1_5, encryptionAlgorithm: .A256CBCHS512),
    payload: Payload(message.data(using: .utf8)!),
    encrypter: Encrypter(keyEncryptionAlgorithm: .RSA1_5, keyEncryptionKey: publicKey, contentEncyptionAlgorithm: .A256CBCHS512)!
)

print(jwe.compactSerializedString) // ey (..) n0.HK (..) pQ.yS (..) PA.AK (..) Jx.hB (..) 7w
```  

<details>

<summary>
Click here for a more detailed description of creating a JWE to encrypt data.
</summary>

<br>

First, we create a header which specifies the algorithms we are going to use  later on to encrypt our data:

> Note that we need to specify two algorithms. One is the [algorithm used to encrypt the randomly generated content encryption key](https://tools.ietf.org/html/rfc7516#section-4.1.1), the other is the actual [content encryption algorithm](https://tools.ietf.org/html/rfc7516#section-4.1.2).

``` swift
let header = JWEHeader(algorithm: .RSAPKCS, encryptionAlgorithm: .AES256CBCHS512)
``` 

Then we specify the data we want to send:

``` swift
let message = "Summer ⛱, Sun ☀️, Cactus 🌵"

let data = message.data(using: .utf8)!

let payload = Payload(data)
```

Finally, we pass the receiver’s public key to an encrypter that will handle all the cryptographic magic for us:

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

``` swift
let publicKey: SecKey = /* ... */

let encrypter = Encrypter(keyEncryptionAlgorithm: .RSAPKCS, keyEncryptionKey: publicKey, contentEncyptionAlgorithm: .AES256CBCHS512)!
```

Now we just put these three parts together to form our JWE:

``` swift
guard let jwe = try? JWE(header: header, payload: payload, encrypter: encrypter) else {
    // Something went wrong!
}

// Enjoy your fresh JWE!
```

Now, you will most probably want to transmit your message, which is now encrypted inside the JWE, to someone else. To do so, you just transmit the serialized JWE which can be obtained as follows:

``` swift
jwe.compactSerializedString // ey (..) n0.HK (..) pQ.yS (..) PA.AK (..) Jx.hB (..) 7w
```

The JWE compact serialization is a URL safe string that can easily be transmitted to a third party using a method of your choice.

</details>

#### Decrypting Received Data

In short:

``` swift
let privateKey: SecKey = /* ... */

let serialization = /* ... */

do {
    let jwe = try JWE(compactSerialization: serialization)
    let payload = try jwe.decrypt(with: privateKey)
    let message = String(data: payload.data(), encoding: .utf8)!

    print(message) // Summer ⛱, Sun ☀️, Cactus 🌵
}
```

<details>

<summary>
Click here for a more detailed description of decrypting a JWE and retrieving its payload.
</summary>

<br>

If you receive a JWE serialization from someone else, you can easily construct a JWE from it:

``` swift
let serialization = /* ... */

do {
	let jwe = try JWE(compactSerialization: serialization)
} catch {
    // Deserialization failed!
}
```

You can then decrypt the JWE using your private key:

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

``` swift
let privateKey: SecKey = /* ... */

guard let payload = try? jwe.decrypt(with: privateKey) else {
    // Decryption failed!
}

// Decryption successful!
```

Now we can read the plain message:

``` swift
let data = payload.data()

let message = String(data: data, encoding: .utf8)! // Summer ⛱, Sun ☀️, Cactus 🌵
```

</details>

### JWK: Representing Keys

A JWK is a JSON data structure that represents a cryptographic key. You could use it, for instance, as the payload of a JWS or a JWE to transmit your public key to a server.

#### Encoding RSA Public Keys

In short:

``` swift
let publicKey: SecKey = /* ... */

// or

let publicKey: Data = /* ... */

try! RSAPublicKey(publicKey: publicKey).jsonString()! // {"kty":"RSA","n":"MHZ4Li4uS2d3","e":"QVFBQg"}
```

<details>

<summary>
Click here for a more detailed description of creating a JWK from an RSA public key.
</summary>

<br>

We currently support creating a JWK from the DER encoding of an RSA public key as specified by [PKCS#1](https://tools.ietf.org/html/rfc3447#appendix-A.1.1). 
This is the format that the [`SecKeyCopyExternalRepresentation`](https://developer.apple.com/documentation/security/1643698-seckeycopyexternalrepresentation) function of iOS’s `Security` framework returns for a `SecKey`.

You can create a JWK directly from such a `SecKey` if it represents an RSA public key:

``` swift
let publicKey: SecKey = /* ... */

let jwk = try! RSAPublicKey(publicKey: publicKey)
```

You can then obtain the JSON for this JWK like this:

``` swift
jwk.jsonString()! // {"kty": "RSA", "n": "MHZ4Li4uS2d3", "e": "QVFBQg"}
```

`RSAPublicKey` also implements `Encodable`, so you can also use Swift’s [`JSONEncoder`](https://developer.apple.com/documentation/foundation/jsonencoder) to encode it.

Alternatively, you can also simply use DER encoded data in PKCS#1 format to initialize a JWK:

``` swift
let publicKey: Data = /* ... */

let jwk = try! RSAPublicKey(publicKey: publicKey)
```

Passing additional parameters that will be included in the JWK’s JSON is easy as well:

``` swift
let publicKey: SecKey = /* ... */

let jwk = try! RSAPublicKey(publicKey: publicKey, additionalParameters: [
    "kid": "123!"
])

jwk.jsonString()! // {"kty": "RSA", "kid": "123!", n": "MHZ4Li4uS2d3", "e": "QVFBQg"}
```

</details>

#### Decoding RSA Public Keys

In short:

``` swift
let json: Data = /* ... */

let publicKey: SecKey = try! RSAPublicKey(data: json).converted(to: SecKey.self)

// or

let publicKey: Data = try! RSAPublicKey(data: json).converted(to: Data.self)
```

<details>

<summary>
Click here for a more detailed description of decoding a JWK JSON into another key format.
</summary>

<br>

If you receive an RSA public key from someone else, you can construct a `SecKey` object or a `Data` object from it. For example to subsequently store the key in an iOS device’s keychain.

First, we construct a JWK from the JSON we received:

``` swift
let json: Data = /* ... */ 

let jwk = try! RSAPublicKey(data: json)
```

Then we create a `SecKey` from it which we could then store in the device’s keychain using [`SecItemAdd`](https://developer.apple.com/documentation/security/1401659-secitemadd):

``` swift
let publicKey: SecKey = try! jwk.converted(to: SecKey.self)
```

Similarly, you can get a key’s DER encoded data in PKCS#1 format:

``` swift
let publicKey: Data = try! jwk.converted(to: Data.self)
```

</details>

## Security

JOSESwift uses the [iOS Security framework](https://developer.apple.com/documentation/security) and [Apple’s CommonCrypto](https://opensource.apple.com//source/CommonCrypto/) for cryptography.

It is designed in a way that it is easy to switch out the implementation for a specific cryptographic operation. Non-iOS users can easily add their own platform independent crypto implementation instead of the ones mentioned above.

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

For security disclosures or related matters, please contact :warning: **Todo:** Add security contact address.

## Contributing

Contributions to the project are encouraged and always welcome. :nerd_face:

If you want to contribute, please submit a pull request. 
For feature requests, discussions or bug reports, just open an issue.

Checkout our [contributing guidelines](.github/CONTRIBUTING.md) for a little more information.

## Resources

You can find detailed information about the relevant JOSE standards in the respective RFCs:

- [RFC-7515:](https://tools.ietf.org/html/rfc7515) JSON Web Signature (JWS)
- [RFC-7516:](https://tools.ietf.org/html/rfc7516) JSON Web Encryption (JWE)
- [RFC-7517:](https://tools.ietf.org/html/rfc7517) JSON Web Key (JWK)
- [RFC-7518:](https://tools.ietf.org/html/rfc7518) JSON Web Algorithms (JWA)

Don’t forget to check our [our wiki](https://github.com/mohemian/jose-ios/wiki) for more detailed documentation.

## Credits

JOSESwift is maintained by [Airside Mobile](https://www.airsidemobile.com).

### Project Authors and Maintainers

[@carol-mohemian](https://github.com/carol-mohemian),
[@daniel-mohemian](https://github.com/daniel-mohemian),
[@gigi-mohemian](https://github.com/gigi-mohemian)

### Reviewers

[@haeser](https://github.com/haeser), [@michael-mohemian](https://github.com/michael-mohemian)

### Thanks

To the following projects, which served us as reference and inspiration during development:

- [Heimdall](https://github.com/henrinormak/Heimdall)
- [Nimbus JOSE + JWT](https://connect2id.com/products/nimbus-jose-jwt)

## License

JOSESwift is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.