# SwiftJOSE

:warning: **This is work in progress.** :warning:

SwiftJOSE is a [JavaScript Object Signing and Encryption (JOSE)](http://jose.readthedocs.io/en/latest) framework written in Swift.

## Features

We plan to support:

- [ ] [JWS](https://tools.ietf.org/html/rfc7515)
- [ ] [JWE](https://tools.ietf.org/html/rfc7516)
- [ ] [JWK](https://tools.ietf.org/html/rfc7517)

## Usage

Below you can find a small code example of how to sign and verify a `JWS` object. For more detailed documentation and other code examples please refer to the [documentation section](https://github.com/mohemian/jose-ios/blob/master/Documentation).

### Sign

To sign a payload and initialize a `JWS` provide a private key corresponding to the chosen signing algorithm.

```swift
import SwiftJOSE

let header = JWSHeader(algorithm: .RS512)
let payload = JWSPayload(message.data(using: .utf8)!)
let signer = RSASigner(key: privateKey)
     
let jws = JWS(header: header, payload: payload, signer: signer)
```

### Verify

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

## Installation

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

## Contributing



TODO: Contribution welcome, link to contributing.md and code of coduct

## Communication

## Testing

To run the project's iOS unit tests select the `SwiftJOSE` scheme and use the `Cmd+U` shortcut or the **Product->Test** menu bar action.  

## Credits

## License
