# Security Policy

## Cryptography

JOSESwift exclusively uses the [iOS Security framework](https://developer.apple.com/documentation/security) and [Apple’s CommonCrypto](https://opensource.apple.com//source/CommonCrypto/) for cryptographic primitives.

At the moment, we do not have plans to accept implementations that make use of cryptographic implementations that are not part of Apple’s iOS SDKs. 

However, we might consider extending the library in a way that would allow the current cryptographic implementation (based on Apple’s SDKs) to _optionally_ be switched out by a different implementation if this enables JOSESwift to run in a pure Swift environment. Please contact us if this is something you are thinking about.

## Supported Versions

Please make sure to always update to the latest version to receive security related patches.

## Reporting a Vulnerability

For security disclosures or related matters, please contact <joseswift@airsidemobile.com>. We will do our best to review and respond to security disclosures with the highest priority.
