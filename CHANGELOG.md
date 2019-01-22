# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
[PSPDFKit's Changelog Format](https://pspdfkit.com/blog/2018/the-challenges-of-changelogs/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Start each entry with one of the following keywords: 

- *API*: For highlighting breaking API changes that require people to change their implementations
- *Adds*: For listing new features
- *Fixes*: For listing bugfixes
- *Changes*: For listing improvements other changes
- *Deprecates*: For listing API deprecations
- *Security*: For highlighting changes related to security vulnerabilities

Include references to issue- or pull-request numbers.
Use active language and present tense.
For convenience, feel free to track changes in the *Unreleased* section upon
merge to master and move them to a respective version upon release.

## [1.4.0] - 2018-12-04

- Changes Swift version from 4.0 to 4.2 ([#127](https://github.com/airsidemobile/JOSESwift/pull/127))
- Changes `CommonCrypto` import to use Swift’s new builtin `CommonCrypto` module instead of the custom `SJCommonCrypto` module ([#127](https://github.com/airsidemobile/JOSESwift/pull/127), [#131](https://github.com/airsidemobile/JOSESwift/pull/131))
