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
    /// RSAES-PKCS1-v1_5
    case RSA1_5 = "RSA1_5"
    /// RSAES OAEP using SHA-1 and MGF1 with SHA-1
    case RSAOAEP = "RSA-OAEP"
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    case RSAOAEP256 = "RSA-OAEP-256"
    /// Direct use of a shared symmetric key as the content encryption key
    case direct = "dir"
}

/// Cryptographic algorithms for content encryption.
///
/// See [RFC 7518, Section 5](https://tools.ietf.org/html/rfc7518#section-5).
public enum ContentEncryptionAlgorithm: String {
    /// AES_256_CBC_HMAC_SHA_512
    case A256CBCHS512 = "A256CBC-HS512"
    /// AES_128_CBC_HMAC_SHA_256
    case A128CBCHS256 = "A128CBC-HS256"
}

/// An algorithm for HMAC calculation.
///
/// - SHA512
/// - SHA256
public enum HMACAlgorithm: String {
    case SHA512
    case SHA256

    var outputLength: Int {
        switch self {
        case .SHA512:
            return 64
        case .SHA256:
            return 32
        }
    }
}

/// An algorithm for compressing the plain text before encryption.
/// List of [supported compression algorithms](https://www.iana.org/assignments/jose/jose.xhtml#web-encryption-compression-algorithms)
///
/// - Deflate: [DEF](https://tools.ietf.org/html/rfc7516#section-4.1.3)
public enum CompressionAlgorithm: String {
    case DEFLATE = "DEF"
    case NONE = "NONE"
}
