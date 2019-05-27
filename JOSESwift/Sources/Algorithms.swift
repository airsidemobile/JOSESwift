//
//  Algorithms.swift
//  JOSESwift
//
//  Created by Carol Capek on 06.02.18.
//  Modified by Jarrod Moldrich on 02.07.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
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

/// An algorithm for signing and verifying.
///
/// - RS512: [RSASSA-PKCS1-v1_5 using SHA-512](https://tools.ietf.org/html/rfc7518#section-3.3)
/// - ES512: [ECDSA P-521 using SHA-512](https://tools.ietf.org/html/rfc7518#section-3.4)
public enum SignatureAlgorithm: String {
    case RS256
    case RS512
    case ES256
    case ES384
    case ES512
}

/// An algorithm for asymmetric encryption and decryption.
///
/// - RSA1_5: [RSAES-PKCS1-v1_5](https://tools.ietf.org/html/rfc7518#section-4.2)
/// - RSAOAEP: [RSAES OAEP using SHA-1 and MGF1 with SHA-1](https://tools.ietf.org/html/rfc7518#section-4.3)
/// - RSAOAEP256: [RSAES OAEP using SHA-256 and MGF1 with SHA-256](https://tools.ietf.org/html/rfc7518#section-4.3)
/// - direct: [Direct Encryption with a Shared Symmetric Key](https://tools.ietf.org/html/rfc7518#section-4.5)
public enum AsymmetricKeyAlgorithm: String, CaseIterable {
    // swiftlint:disable:next identifier_name
    case RSA1_5 = "RSA1_5"
    case RSAOAEP = "RSA-OAEP"
    case RSAOAEP256 = "RSA-OAEP-256"
    case direct = "dir"
}

/// An algorithm for symmetric encryption and decryption.
///
/// - A256CBCHS512: [AES_256_CBC_HMAC_SHA_512](https://tools.ietf.org/html/rfc7518#section-5.2.5)
/// - A128CBCHS256: [AES_128_CBC_HMAC_SHA_256](https://tools.ietf.org/html/rfc7518#section-5.2.3)
public enum SymmetricKeyAlgorithm: String {
    case A256CBCHS512 = "A256CBC-HS512"
    case A128CBCHS256 = "A128CBC-HS256"

    var hmacAlgorithm: HMACAlgorithm {
        switch self {
        case .A256CBCHS512:
            return .SHA512
        case .A128CBCHS256:
            return .SHA256
        }
    }

    var keyLength: Int {
        switch self {
        case .A256CBCHS512:
            return 64
        case .A128CBCHS256:
            return 32
        }
    }

    var initializationVectorLength: Int {
        switch self {
        case .A256CBCHS512:
            return 16
        case .A128CBCHS256:
            return 16
        }
    }

    func checkKeyLength(for key: Data) -> Bool {
        switch self {
        case .A256CBCHS512:
            return key.count == 64
        case .A128CBCHS256:
            return key.count == 32
        }
    }

    func retrieveKeys(from inputKey: Data) throws -> (hmacKey: Data, encryptionKey: Data) {
        switch self {
        case .A256CBCHS512:
            guard checkKeyLength(for: inputKey) else {
                throw JWEError.keyLengthNotSatisfied
            }

            return (inputKey.subdata(in: 0..<32), inputKey.subdata(in: 32..<64))

        case .A128CBCHS256:
            guard checkKeyLength(for: inputKey) else {
                throw JWEError.keyLengthNotSatisfied
            }
            return (inputKey.subdata(in: 0..<16), inputKey.subdata(in: 16..<32))
        }
    }

    func authenticationTag(for hmac: Data) -> Data {
        switch self {
        case .A256CBCHS512:
            return hmac.subdata(in: 0..<32)
        case .A128CBCHS256:
            return hmac.subdata(in: 0..<16)
        }
    }
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
