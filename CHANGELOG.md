# Changelog

All notable changes to this project will be documented in this file.

Include references to issue- or pull-request numbers.

## [3.0.0] - 2024-08-27

### What's Changed

* added watchos build-ability to SPM package by @mcecunda in https://github.com/airsidemobile/JOSESwift/pull/264
* Fix linter warnings by @antonyalkmim in https://github.com/airsidemobile/JOSESwift/pull/293
* Update target platforms and fix tests by @daniel-moh in https://github.com/airsidemobile/JOSESwift/pull/310
* Add support for public and private header parameters by @daniel-moh in https://github.com/airsidemobile/JOSESwift/pull/312
* [JWE] Added support for `A256GCM` and `A128GCM` by @tobihagemann in https://github.com/airsidemobile/JOSESwift/pull/278
* Updates search path for Mac silicon SwiftLint functionality in Xcode by @haeser in https://github.com/airsidemobile/JOSESwift/pull/311
* Add ECDH support for JWE Key Management continuation of #268 by @anthony-dedieu-ariadnext in https://github.com/airsidemobile/JOSESwift/pull/314
* Add support for PBES2 by @tobihagemann in https://github.com/airsidemobile/JOSESwift/pull/304
* Add support for A192CBC-HS384 and A192GCM by @daniel-moh in https://github.com/airsidemobile/JOSESwift/pull/341
* Allow for plugging in user-provided crypto implementations via customization API by @daniel-moh in https://github.com/airsidemobile/JOSESwift/pull/343
* Reorganize source files into directories by @daniel-moh in https://github.com/airsidemobile/JOSESwift/pull/344
* Remove deprecated APIs by @daniel-moh in https://github.com/airsidemobile/JOSESwift/pull/345
* Update signer and verifier init param name and fix typos by @daniel-moh in https://github.com/airsidemobile/JOSESwift/pull/346

### New Contributors
* @mcecunda made their first contribution in https://github.com/airsidemobile/JOSESwift/pull/264
* @antonyalkmim made their first contribution in https://github.com/airsidemobile/JOSESwift/pull/293
* @anthony-dedieu-ariadnext made their first contribution in https://github.com/airsidemobile/JOSESwift/pull/314
* @daniel-moh made their first contribution in https://github.com/airsidemobile/JOSESwift/pull/310

**Full Changelog**: https://github.com/airsidemobile/JOSESwift/compare/2.4.0...3.3.0

## [2.4.0] - 2021-04-20

- Use timing safe byte comparison for AES CBC MAC checks (#259)
- Add support for JWS HS256, HS384, and HS512 algorithms (#258)
- Bump kramdown from 2.3.0 to 2.3.1 (#255)
- Update SPM installation instructions (#252)
- Automate publishing releases on GitHub (#249)

## [2.3.1] - 2020-12-14

- Stop installing SwiftLint when it's not installed (#246)

## [2.3.0] - 2020-11-11

- Add parsed JWK header parameter (#240)
- Apply Xcode12 recommended settings (#236)
- Add macOS to platforms (#233)
- Update danger (#232)

## [2.2.1] - 2020-06-24

- Copy additional parameters when updating JWT with keyId (#225)
- Add SPM installation to readme (#224)

## [2.2.0] - 2020-06-17

- Swift package support ([#221](https://github.com/airsidemobile/JOSESwift/pull/221)) via [@rogermadsen](https://github.com/rogermadsen)
- Added JWK thumbprint computation ([#220](https://github.com/airsidemobile/JOSESwift/pull/220)) via [@Torsph](https://github.com/Torsph)

## [2.1.0] - 2020-02-24

- Deprecated old encrypter and decrypter APIs ([#216](https://github.com/airsidemobile/JOSESwift/pull/216)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Added A128KW, A192KW, and A256KW algorithms ([#211](https://github.com/airsidemobile/JOSESwift/pull/211)) via [@mtamu](https://github.com/mtamu)
- Changed internal JWE encryption and decryption flows ([#210](https://github.com/airsidemobile/JOSESwift/pull/210)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Changed CI to CircleCI ([#205](https://github.com/airsidemobile/JOSESwift/pull/205)) via [@haeser](https://github.com/haeser)
- Dried up signing roundtrip tests ([#198](https://github.com/airsidemobile/JOSESwift/pull/198)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Added full Sonarqube analysis to pull requests ([#201](https://github.com/airsidemobile/JOSESwift/pull/201)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Updated Sonarqube lane to work with the Xcode 11 coverage report format ([#193](https://github.com/airsidemobile/JOSESwift/pull/193)) via [@daniel-mohemian](https://github.com/daniel-mohemian)

## [2.0.0] - 2019-11-20

- Fixes copyright update in prepare lane ([(#191)](https://github.com/airsidemobile/JOSESwift/pull/191)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Updates travis build environment ([(#190)](https://github.com/airsidemobile/JOSESwift/pull/190)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Adds support for RSA PSS and RS384 signatures ([(#188)](https://github.com/airsidemobile/JOSESwift/pull/188)) via [@JohanObrink](https://github.com/JohanObrink)
- Removes twitter handle from readme again ([(#187)](https://github.com/airsidemobile/JOSESwift/pull/187)) via [@carol-mohemian](https://github.com/carol-mohemian)
- Removes .swift-version file ([(#185)](https://github.com/airsidemobile/JOSESwift/pull/185)) via [@carol-mohemian](https://github.com/carol-mohemian)
- Adds Ivans twitter handle ([(#184)](https://github.com/airsidemobile/JOSESwift/pull/184)) via [@carol-mohemian](https://github.com/carol-mohemian)
- Updates fastlane ([(#182)](https://github.com/airsidemobile/JOSESwift/pull/182)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Adds missing license headers and automate their yearly updates ([(#179)](https://github.com/airsidemobile/JOSESwift/pull/179)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Extends JOSESwift Errors with localAuthentication ([(#173)](https://github.com/airsidemobile/JOSESwift/pull/173)) via [@Niklas01](https://github.com/Niklas01)
- Bumps swift version in podspec and version file ([(#167)](https://github.com/airsidemobile/JOSESwift/pull/167)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Bumps fastlane to resolve mini_magic dependency warning ([(#164)](https://github.com/airsidemobile/JOSESwift/pull/164)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Adds security policy ([(#159)](https://github.com/airsidemobile/JOSESwift/pull/159)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Adds simple Sonarqube setup ([(#158)](https://github.com/airsidemobile/JOSESwift/pull/158)) via [@daniel-mohemian](https://github.com/daniel-mohemian)

## [1.8.1] - 2019-06-27

- Adds tests for conversion from ASN.1 encoded EC signatures to raw EC signatures ([#160](https://github.com/airsidemobile/JOSESwift/pull/160)) via [@mschwaig](https://github.com/mschwaig)
- Adds support for EC keys that are stored inside the Secure Enclave ([#156](https://github.com/airsidemobile/JOSESwift/pull/156)) via [@mschwaig](https://github.com/mschwaig)
- Changes swift version to Swift 5 [#154](https://github.com/airsidemobile/JOSESwift/pull/154)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Adds pull request linting in Danger ([#153](https://github.com/airsidemobile/JOSESwift/pull/153)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Adds a SwiftLint build phase and fixes many violations ([#151](https://github.com/airsidemobile/JOSESwift/pull/151)) via [@xavierLowmiller](https://github.com/xavierLowmiller)

## [1.8.0] - 2019-03-18

- Adds A128CBCHS256 support ([#147](https://github.com/airsidemobile/JOSESwift/pull/147)) via [@ramunasjurgilas](https://github.com/ramunasjurgilas)
- Adds "zip" support ([#145](https://github.com/airsidemobile/JOSESwift/pull/145)) via [@fhaeser](https://github.com/fhaeser)

## [1.7.0] - 2019-02-19

- Adds a new features section in the readme ([#143](https://github.com/airsidemobile/JOSESwift/pull/143)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Adds support for RSA-OAEP ([#95](https://github.com/airsidemobile/JOSESwift/pull/95), [#142](https://github.com/airsidemobile/JOSESwift/pull/142)) via [@garrefa](https://github.com/garrefa)

## [1.6.0] - 2019-01-25

- Adds support for RSA-OAEP-256 ([#135](https://github.com/airsidemobile/JOSESwift/pull/135)) via [@stulevine](https://github.com/stulevine)

## [1.5.0] - 2019-01-23

- Changes the way elliptic curve keys are decoded to work around [#86](https://github.com/airsidemobile/JOSESwift/issues/86) until [#120](https://github.com/airsidemobile/JOSESwift/pull/120) is merged ([#137](https://github.com/airsidemobile/JOSESwift/pull/137)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Adds a changelog ([#136](https://github.com/airsidemobile/JOSESwift/pull/136)) via [@daniel-mohemian](https://github.com/daniel-mohemian)
- Changes travis to use builtin homebrew addon ([#133](https://github.com/airsidemobile/JOSESwift/pull/133)) via [@stephengroat](https://github.com/stephengroat)
- Security: Change fastlane version to fix [#129](https://github.com/airsidemobile/JOSESwift/issues/129) ([#130](https://github.com/airsidemobile/JOSESwift/pull/130)) via [@alex-mohemian](https://github.com/alex-mohemian)
- Adds support for elliptic curve algorithms for JWS and elliptic curve keys for JWK ([#88](https://github.com/airsidemobile/JOSESwift/pull/88)) via [@jarrodmoldrich](https://github.com/jarrodmoldrich)

## [1.4.0] - 2018-12-04

- Changes Swift version from 4.0 to 4.2 ([#127](https://github.com/airsidemobile/JOSESwift/pull/127)) via [@xavierLowmiller](https://github.com/xavierLowmiller)
- Changes `CommonCrypto` import to use Swift’s new builtin `CommonCrypto` module instead of the custom `SJCommonCrypto` module ([#127](https://github.com/airsidemobile/JOSESwift/pull/127), [#131](https://github.com/airsidemobile/JOSESwift/pull/131)) via [@daniel-mohemian](https://github.com/daniel-mohemian)

TODO: Add old versions and especially contributors from old versions! See [#144](https://github.com/airsidemobile/JOSESwift/issues/144).
