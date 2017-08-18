# SwiftJOSE

SwiftJOSE is a [JavaScript Object Signing and Encryption (JOSE)](http://jose.readthedocs.io/en/latest) framework written in Swift.

⚠️ This is work in progress.

## Features

We plan to support:

- [ ] [JWS](https://tools.ietf.org/html/rfc7515)
- [ ] [JWE](https://tools.ietf.org/html/rfc7516)
- [ ] [JWK](https://tools.ietf.org/html/rfc7517)

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