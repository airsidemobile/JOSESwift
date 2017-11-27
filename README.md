# SwiftJOSE :bird: 

:warning: **This is work in progress.** :warning:

SwiftJOSE is a [JavaScript Object Signing and Encryption (JOSE)](http://jose.readthedocs.io/en/latest) framework written in Swift.

## Features

We plan to support:

- [ ] [JWS](https://tools.ietf.org/html/rfc7515)
  - [x] Supporting signing/verifying with RSASSA-PKCS1-v1_5 using SHA-512
- [ ] [JWE](https://tools.ietf.org/html/rfc7516)
  - [x] Supporting key encryption/decryption with RSAES-PKCS1-v1_5
- [ ] [JWK](https://tools.ietf.org/html/rfc7517)

## Supported Algorithms

At the moment the implemented algorithms are limited to a minimum. Therefore, to create and verify the signature of a `JWS` only `RSASSA-PKCS1-v1_5 using SHA-512` can be used. `JWE` supports `RSAES-PKCS1-v1_5` for key encryption/decryption.

## Usage

Below you can find a small code example of how to sign and verify a `JWS` object. For more detailed documentation and other code examples please refer to the [documentation section](https://github.com/mohemian/jose-ios/blob/master/Documentation).

### Sign :lock_with_ink_pen:

To sign a payload and initialize a `JWS` provide a private key corresponding to the chosen signing algorithm.

```swift
import SwiftJOSE

let header = JWSHeader(algorithm: .RS512)
let payload = JWSPayload(message.data(using: .utf8)!)
let signer = RSASigner(key: privateKey)
     
let jws = JWS(header: header, payload: payload, signer: signer)
```

### Verify :white_check_mark::vs::negative_squared_cross_mark:

To verify a signature of a received compact serialized `JWS`, initialize a `JWS` with the compact serialization and create a `Verifier` with the corresponding public key of the signature's private key.

``` swift
import SwiftJOSE

let jws = JWS(compactSerialization: serializedJWS)
        
let verifier = RSAVerifier(key: publicKey)
if jws.validates(against: verifier) {
    print("Signature correct.")
} else {
    print("Signature wrong")
}
```

### Encrypt :closed_lock_with_key:


### Decrypt :unlock:

## Installation :hammer_and_wrench:

### Carthage

Add the following to your `Cartfile`:

``` shell
github "mohemian/jose-ios"
```

### CocoaPods

Add the following to your `Podfile`:

``` ruby
pod 'SwiftJOSE', git: 'git@github.com:mohemian/jose-ios.git',
```

### Swift Package Manager

Add the following dependency to your `Package.swift`:

``` swift
dependencies: [
    .package(url: "https://github.com/mohemian/jose-ios.git", from: "1.0.0")
]
```

## Contributing :woman_technologist::man_technologist:

If you want to contribute to this project don't hesitate to check out the [Contribution Guidelines](https://github.com/mohemian/jose-ios/blob/master/CONTRIBUTING.md). 

## Credits

## License
