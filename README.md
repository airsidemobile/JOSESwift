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
	- [Signing data for transmission](#securing-data-for-transmission)
	- [Verifying data received from someone else](#verifying-received-data)
- [JWE: Encryption and Decryption](#jwe-encryption-and-decryption)
	- [Encrypting data for transmission](#encrypting-data-for-transmission)
	- [Decrypting data received from someone else](#decrypting-received-data)
- [JWK: Representing Keys](#jwk-representing-keys)
	- [Encoding RSA Public Keys](#encoding-rsa-public-keys)
	- [Decoding RSA Public Keys](#decoding-rsa-public-keys)
### JWS: Digital Signatures

A JWS encapsulates and secures data using a digital signature which can be verified by the receiver of the JWS.

A JWS consists of three parts:

- Header
- Payload
- Signature

#### Signing Data for Transmission

*In short:*

``` swift
let serialization = JWS(
    header: JWSHeader(algorithm: .RS512),
    payload: Payload("Do you knwo the way to San Jose?".data(using: .utf8)!),
    signer: Signer(signingAlgorithm: .RS512, privateKey: key)
)!.compactSerializedString
```  

*Now for a more detailed description of what’s going on above.*

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
let privateKey: SecKey = /* ... */

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

#### Verifying Received Data

*In short:* 

``` swift
guard 
    let jws = try? JWS(compactSerialization: serialization),
    jws.isValid(for: publicKey),
    let message = String(data: jws.payload.data(), encoding: .utf8)
else {
    // Signature is invalid!
}

message // Do you know the way to San Jose?
```

*Now for a more detailed description of what’s going on above.*

If you receive a JWS serialization from someone else, you can easily construct a JWS from it:

``` swift
let serialization = /* ... */

let jws = try! JWS(compactSerialization: serialization)
```

You can then check it’s signature using the public key of the sender:

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

``` swift
let piublicKey: SecKey = /* ... */

guard jws.isValid(for: publicKey) else {
    // Signature is invalid!
}

// Signature is valid!
```

Now we can trust the message, which we get from the JWS as follows:

``` swift
let data = jws.payload.data()

let message = String(data: data, encoding: .utf8)! // Do you know the way to San Jose?
```

### JWE: Encryption and Decryption

A JWE encapsulates and secures data by encrypting it. It can be decrypted by the receiver of the JWE.

A JWE consists of five parts:

- Header
- Encrypted Key
- Initialization Vector
- Additional Authenticated Data
- Ciphertext
- Authentication Tag

In order to construct a JWE we will only need to provide the following parts, though:

- Header
- Plaintext
- Encrypter

#### Encrypting Data for Transmission

*In short:*

``` swift
let serialization = JWE(
    header: JWEHeader(algorithm: .RSAPKCS, encryptionAlgorithm: .AES256CBCHS512),
    payload: Payload("Do you know the way to San Jose?".data(using: .utf8)!),
    encrypter: Encrypter(keyEncryptionAlgorithm: .RSAPKCS, keyEncryptionKey: publicKey, contentEncyptionAlgorithm: .AES256CBCHS512)
)!.compactSerializedString
```  

*Now for a more detailed description of what’s going on above.*

First we create a header which specifies the algorithms we are going to use  later on to encrypt our data:

> Note that we need to specify two algorithms. One is the [algorithm used to encrypt the content encryption key](https://tools.ietf.org/html/rfc7516#section-4.1.1), the other is the actual [content encryption algorithm](https://tools.ietf.org/html/rfc7516#section-4.1.2).

``` swift
let header = JWEHeader(algorithm: .RSAPKCS, encryptionAlgorithm: .AES256CBCHS512)
``` 

Then we specify the data we want to send:

``` swift
let message = "Do you know the way to San Jose?"

let data = message.data(using: .utf8)!

let payload = Payload(data)
```

Finally we pass the receiver’s public key to an encrypter that will handle all the cryptographic magic for us:

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

``` swift
let publicKey: SecKey = /* ... */

let encrypter = Encrypter(keyEncryptionAlgorithm: .RSAPKCS, keyEncryptionKey: publicKey, contentEncyptionAlgorithm: .AES256CBCHS512)
```

Now we just put these three parts together to form our JWE:

``` swift
guard let jwe = JWE(header: header, payload: payload, encrypter: encrypter) else {
    // Something went wrong!
}

// Enjoy your fresh JWE!
```

Now, you will most probably want to transmit your message, which is now encrypted inside the JWE, to someone else. To do so, you just transmit the serialized JWE which can be obtained as follows:

``` swift
jwe.compactSerializedString // ey (...) n0.cF (...) qQ.rx (...) CA.0B (...) AG.Ez (...) eY
```

The JWE compact serialization is a URL safe string that can easily be transmitted to a third party using a method of your choice.

#### Decrypting Received Data

*In short:* 

``` swift
guard 
    let jwe = try? JWE(compactSerialization: serialization),
    let payload = jwe.decrypt(with: privateKey)
    let message = String(data: payload.data(), encoding: .utf8)
else {
    // Decryption failed!
}

message // Do you know the way to San Jose?
```

*Now for a more detailed description of what’s going on above.*

If you receive a JWE serialization from someone else, you can easily construct a JWE from it:

``` swift
let serialization = /* ... */

let jwe = try! JWE(compactSerialization: serialization)
```

You can then decrypt the JWE using your private key:

> Please note that as of now we use the `SecKey` class from the iOS `Security` framework to represent our keys. We are working on replacing this with something platform independent so non-iOS users can use the framework with ease.

``` swift
let privateKey: SecKey = /* ... */

guard let payload = jwe.decrypt(with: privateKey) else {
    // Decryption failed!
}

// Decryption successful!
```

Now we can read the plain message:

``` swift
let data = payload.data()

let message = String(data: data, encoding: .utf8)! // Do you know the way to San Jose?
```

### JWK: Representing Keys

JWK is a JSON data structure that represents a cryptographic key. For instance, you could use it as payload of a JWS or a JWE to transmit your public key to a server.

#### Encoding RSA Public Keys

*In short:*

``` swift
try! RSAPublicKey(publicKey: publicKey).jsonString()! // {"kty":"RSA","n":"MHZ4Li4uS2d3","e":"QVFBQg"}
```

*Now for a more detailed description of what’s going on above.*

We currently support creating a JWK from the DER encoding of an RSA public key represented as specified by [PKCS#1](https://tools.ietf.org/html/rfc3447#appendix-A.1.1). 
This is the format that the [`SecKeyCopyExternalRepresentation`](https://developer.apple.com/documentation/security/1643698-seckeycopyexternalrepresentation) function of iOS’s `Security` framework returns for a `SecKey`.

You can create a JWK directly from such a `SecKey` if it represents an RSA public key:

``` swift
let publicKey: SecKey = /* ... */

let jwk = try! RSAPublicKey(publicKey: publicKey)
```

You can then obtain the JSON for this JWK like this:

``` swift
jwk.jsonString()! // {"kty":"RSA","n":"MHZ4Li4uS2d3","e":"QVFBQg"}
```

`RSAPublicKey` also implements `Encodable`, so you can also use Swift’s [`JSONEncoder`](https://developer.apple.com/documentation/foundation/jsonencoder) to encode it.

Alternatively, you can also use DER encoded data in PKCS#1 format to initialize a JWK:

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
```

#### Decoding RSA Public Keys

*In short:*

``` swift
let key = try! RSAPublicKey(data: json).converted(to: SecKey.self)
```

*Now for a more detailed description of what’s going on above.*

If you receive an RSA public key from someone else, you can construct a `Data` object or a `SecKey` object from it in order to subsequently store the key in an iOS device’s keychain for example.

First we construct a JWK from the JSON we received:

``` swift
let serverKeyJSON: Data = /* ... */ 

let jwk = try! RSAPublicKey(data: serverKeyJSON)
```

Then we create a `SecKey` from it which we could then store in the device’s keychain using [`SecItemAdd`](https://developer.apple.com/documentation/security/1401659-secitemadd) for example:

``` swift
let key: SecKey = try! jwk.converted(to: SecKey.self)
```

Similarly you can get a key’s DER encoded data in PKCS#1 format:

``` swift
let key: Data = try! jwk.converted(to: Data.self)
```

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