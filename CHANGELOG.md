# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
[PSPDFKit's Changelog Format](https://pspdfkit.com/blog/2018/the-challenges-of-changelogs/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

If applicable, start each entry with one of the following keywords: 

- *API*: For highlighting breaking API changes that require people to change their implementations
- *Adds*: For listing new features
- *Fixes*: For listing bugfixes
- *Changes*: For listing improvements and other changes
- *Deprecates*: For listing API deprecations
- *Security*: For highlighting changes related to security vulnerabilities

Include references to issue- or pull-request numbers.
Use active language and present tense.
For convenience, please track any of your changes in the *Unreleased* section 
so they can be moved to a respective version upon release.

## Unreleased

Add your changes here.

## [1.7.0] - 2019-02-19

- Adds a new features section in the readme ([#143](https://github.com/airsidemobile/JOSESwift/pull/143)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Adds support for RSA-OAEP ([#95](https://github.com/airsidemobile/JOSESwift/pull/95), [#142](https://github.com/airsidemobile/JOSESwift/pull/142)) via [@garrefa](https://github.com/garrefa)

## [1.6.0] - 2019-01-25

- Adds support for RSA-OAEP-256 ([#135](https://github.com/airsidemobile/JOSESwift/pull/135)) via [@stulevine](https://github.com/stulevine)

## [1.5.0] - 2019-01-23

- Changes the way elliptic curve keys are decoded to work around [#86](https://github.com/airsidemobile/JOSESwift/issues/86) until [#120](https://github.com/airsidemobile/JOSESwift/pull/120) is merged ([#137](https://github.com/airsidemobile/JOSESwift/pull/137)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Adds a changelog ([#136](https://github.com/airsidemobile/JOSESwift/pull/136)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Changes travis to use builtin homebrew addon ([#133](https://github.com/airsidemobile/JOSESwift/pull/133))  via [@stephengroat](https://github.com/stephengroat)
- Security: Change fastlane version to fix [#129](https://github.com/airsidemobile/JOSESwift/issues/129) ([#130](https://github.com/airsidemobile/JOSESwift/pull/130)) via [@alex-mohemian](https://github.com/alex-mohemian)
- Adds support for elliptic curve algorithms for JWS and elliptic curve keys for JWK ([#88](https://github.com/airsidemobile/JOSESwift/pull/88)) via [@jarrodmoldrich](https://github.com/jarrodmoldrich)

## [1.4.0] - 2018-12-04

- Changes Swift version from 4.0 to 4.2 ([#127](https://github.com/airsidemobile/JOSESwift/pull/127)) via [@xavierLowmiller](https://github.com/xavierLowmiller)
- Changes `CommonCrypto` import to use Swift’s new builtin `CommonCrypto` module instead of the custom `SJCommonCrypto` module ([#127](https://github.com/airsidemobile/JOSESwift/pull/127), [#131](https://github.com/airsidemobile/JOSESwift/pull/131)) via [@daniel-mohemian](https://github.com/daniel-mohemian)

TODO: Add old versions and especially contributors from old versions! See [#144](https://github.com/airsidemobile/JOSESwift/issues/144).
