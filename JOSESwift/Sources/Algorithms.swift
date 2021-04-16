//
//  Algorithms.swift
//  JOSESwift
//
//  Created by Carol Capek on 06.02.18.
//  Modified by Jarrod Moldrich on 02.07.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import Foundation

/// Cryptographic algorithms for digital signatures and MACs.
///
/// See [RFC 7518, Section 3](https://tools.ietf.org/html/rfc7518#section-3).
public enum SignatureAlgorithm: String {
    /// HMAC using SHA-256
    case HS256
    /// HMAC using SHA-384
    case HS384
    /// HMAC using SHA-512
    case HS512
    /// RSASSA-PKCS1-v1_5 using SHA-256
    case RS256
    /// RSASSA-PKCS1-v1_5 using SHA-384
    case RS384
    /// RSASSA-PKCS1-v1_5 using SHA-256
    case RS512
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    @available(iOS 11, *) case PS256
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    @available(iOS 11, *) case PS384
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    @available(iOS 11, *) case PS512
    /// ECDSA P-256 using SHA-256
    case ES256
    /// ECDSA P-384 using SHA-384
    case ES384
    /// ECDSA P-521 using SHA-512
    case ES512
}

/// Cryptographic algorithms for key management.
///
/// See [RFC 7518, Section 4](https://tools.ietf.org/html/rfc7518#section-4).
public enum KeyManagementAlgorithm: String, CaseIterable {
    /// Key encryption using RSAES-PKCS1-v1_5
    case RSA1_5 = "RSA1_5"
    /// Key encryption using RSAES OAEP using SHA-1 and MGF1 with SHA-1
    case RSAOAEP = "RSA-OAEP"
    /// Key encryption using RSAES OAEP using SHA-256 and MGF1 with SHA-256
    case RSAOAEP256 = "RSA-OAEP-256"
    // Key wrapping using AES Key Wrap with default initial value using 128-bit key
    case A128KW
    // Key wrapping using AES Key Wrap with default initial value using 192-bit key
    case A192KW
    // Key wrapping using AES Key Wrap with default initial value using 1256-bit key
    case A256KW
    /// Direct encryption using a shared symmetric key as the content encryption key
    case direct = "dir"
}

/// Cryptographic algorithms for content encryption.
///
/// See [RFC 7518, Section 5](https://tools.ietf.org/html/rfc7518#section-5).
public enum ContentEncryptionAlgorithm: String {
    /// Content encryption using AES_256_CBC_HMAC_SHA_512
    case A256CBCHS512 = "A256CBC-HS512"
    /// Content encryption using AES_128_CBC_HMAC_SHA_256
    case A128CBCHS256 = "A128CBC-HS256"
}

/// An algorithm for HMAC calculation.
///
/// - SHA512
/// - SHA384
/// - SHA256
public enum HMACAlgorithm: String {
    case SHA512
    case SHA384
    case SHA256

    var outputLength: Int {
        switch self {
        case .SHA512:
            return 64
        case .SHA384:
            return 48
        case .SHA256:
            return 32
        }
    }
}

/// An algorithm for JWK Thumbprint calculation.
///
/// - SHA256
public enum JWKThumbprintAlgorithm: String {
    case SHA256
}

/// An algorithm for compressing the plain text before encryption.
/// List of [supported compression algorithms](https://www.iana.org/assignments/jose/jose.xhtml#web-encryption-compression-algorithms)
///
/// - Deflate: [DEF](https://tools.ietf.org/html/rfc7516#section-4.1.3)
public enum CompressionAlgorithm: String {
    case DEFLATE = "DEF"
    case NONE = "NONE"
}

// MARK: - Deprecated API

@available(*, deprecated, message: "Use `KeyManagementAlgorithm` instead")
public typealias AsymmetricKeyAlgorithm = KeyManagementAlgorithm

@available(*, deprecated, message: "Use `ContentEncryptionAlgorithm` instead")
public typealias SymmetricKeyAlgorithm = ContentEncryptionAlgorithm
