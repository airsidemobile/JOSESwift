//
//  Algorithms.swift
//  JOSESwift
//
//  Created by Carol Capek on 06.02.18.
//  Modified by Jarrod Moldrich on 02.07.18.
//  Refactored by Marius Tamulis on 2019-03-12.
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
import CommonCrypto

public protocol Algorithm {
    var rawValue: String { get }

    init?(rawValue: String)
}

public extension Algorithm {
    func equals<A: Algorithm>(_ other: A) -> Bool {
        return equals(other as Algorithm)
    }

    func equals(_ other: Algorithm) -> Bool {
        return rawValue == other.rawValue
    }
}

extension Optional where Wrapped: Algorithm {
    func wrappedType() -> Wrapped.Type {
        return type(of: self.unsafelyUnwrapped)
    }
}

public struct AlgorithmFactory {
    @available(*, unavailable) private init() {}

    static func createKeyAlgorithm(rawValue: String) -> KeyAlgorithm? {
        let keyAlgTypes: [Algorithm.Type] = [AsymmetricKeyAlgorithm.self, SymmetricKeyAlgorithm.self]
        return getInstance(rawType: rawValue, algorithmTypes: keyAlgTypes) as? KeyAlgorithm

    }

    static func createContentAlgorithm(rawValue: String) -> ContentAlgorithm? {
        let contentAlgTypes: [Algorithm.Type] = [SymmetricContentAlgorithm.self]
        return getInstance(rawType: rawValue, algorithmTypes: contentAlgTypes) as? ContentAlgorithm
    }

    private static func getInstance(rawType: String, algorithmTypes: [Algorithm.Type]) -> Algorithm? {
        for algType in algorithmTypes {
            if let algCase = algType.init(rawValue: rawType) {
                return algCase
            }
        }

        return nil
    }
}

/// An algorithm for signing and verifying.
///
/// - RS512: [RSASSA-PKCS1-v1_5 using SHA-512](https://tools.ietf.org/html/rfc7518#section-3.3)
/// - ES512: [ECDSA P-521 using SHA-512](https://tools.ietf.org/html/rfc7518#section-3.4)
public enum SignatureAlgorithm: String, Algorithm {
    case RS256 = "RS256"
    case RS512 = "RS512"
    case ES256 = "ES256"
    case ES384 = "ES384"
    case ES512 = "ES512"
}

/// Both key encryption and content encryption symmetric algorithms.
public protocol SymmetricAlgorithm: Algorithm {
    var defaultInitialValue: Data { get }
    var keyLength: Int { get }
    var initializationVectorLength: Int { get }

    func retrieveKeys(from inputKey: Data) throws -> (hmacKey: Data, encryptionKey: Data)
}

public extension SymmetricAlgorithm {
    var defaultInitialValue: Data {
        // Same as rfc3394 IV, [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]
        return Data(bytes: CCrfc3394_iv, count: CCrfc3394_ivLen)
    }

    var keyLength: Int {
        return 0
    }

    var initializationVectorLength: Int {
        return CCrfc3394_ivLen
    }

    func retrieveKeys(from inputKey: Data) throws -> (hmacKey: Data, encryptionKey: Data) {
        throw JWEError.keyLengthNotSatisfied
    }
}

// Covers all asymmetric algorythms, but RFC only defines asym. algorithms for key encryption.
public protocol AsymmetricAlgorithm: KeyAlgorithm {}

public protocol ContentAlgorithm: SymmetricAlgorithm {
    //static func == <A: AnyAlgorithm>(lhs: ContentEncryptionAlgorithm, rhs: A) -> Bool
} // TODO: think about extending SymmetricAlgorithm

public protocol KeyAlgorithm: Algorithm {
    //static func == <A: AnyAlgorithm>(lhs: KeyEncryptionAlgorithm, rhs: A) -> Bool
}

/// An algorithm for asymmetric JWE key encryption and decryption.
///
/// - RSA1_5: [RSAES-PKCS1-v1_5](https://tools.ietf.org/html/rfc7518#section-4.2)
/// - RSAOAEP: [RSAES OAEP using SHA-1 and MGF1 with SHA-1](https://tools.ietf.org/html/rfc7518#section-4.3)
/// - RSAOAEP256: [RSAES OAEP using SHA-256 and MGF1 with SHA-256](https://tools.ietf.org/html/rfc7518#section-4.3)
/// - direct: [Direct Encryption with a Shared Symmetric Key](https://tools.ietf.org/html/rfc7518#section-4.5)
public enum AsymmetricKeyAlgorithm: String, CaseIterable, KeyAlgorithm, AsymmetricAlgorithm {
    case RSA1_5 = "RSA1_5"
    case RSAOAEP = "RSA-OAEP"
    case RSAOAEP256 = "RSA-OAEP-256"
    case direct = "dir"
}

/// An algorithm for symmetric JWE key encryption and decryption.
///
/// - A128KW: [Key Wrapping with AES-128 Key Wrap](https://tools.ietf.org/html/rfc7518#section-4.4)
/// - A192KW: [Key Wrapping with AES-192 Key Wrap](https://tools.ietf.org/html/rfc7518#section-4.4)
/// - A256KW: [Key Wrapping with AES-256 Key Wrap](https://tools.ietf.org/html/rfc7518#section-4.4)
public enum SymmetricKeyAlgorithm: String, CaseIterable, KeyAlgorithm, SymmetricAlgorithm {
    case A128KW = "A128KW"
    case A192KW = "A192KW"
    case A256KW = "A256KW"

    var hmacAlgorithm: HMACAlgorithm {
        // TODO: Perhaps refactor and remove.
        return .none
    }

    public var keyLength: Int {
        switch self {
        case .A128KW:
            return 16
        case .A192KW:
            return 24
        case .A256KW:
            return 32
        }
    }

    public var initializationVectorLength: Int {
        switch self {
        case .A128KW, .A192KW, .A256KW:
            return 16
        }
    }

    func checkKeyLength(for key: Data) -> Bool {
        return key.count == keyLength
    }

    public func retrieveKeys(from inputKey: Data) throws -> (hmacKey: Data, encryptionKey: Data) {
        guard checkKeyLength(for: inputKey) else {
            throw JWEError.keyLengthNotSatisfied
        }

        // TODO: Perhaps refactor to optional, these algorithms do not have HMAC.
        return (Data(), inputKey)
    }

    func authenticationTag(for hmac: Data) -> Data {
        // TODO: Perhaps refactor to optional, these algorithms do not have HMAC.
        return Data()
    }
}


/// An algorithm for symmetric JWE content encryption and decryption.
///
/// - A128CBCHS256: [AES_128_CBC_HMAC_SHA_256](https://tools.ietf.org/html/rfc7518#section-5.2.3)
/// - A256CBCHS512: [AES_256_CBC_HMAC_SHA_512](https://tools.ietf.org/html/rfc7518#section-5.2.5)
public enum SymmetricContentAlgorithm: String, CaseIterable, ContentAlgorithm, SymmetricAlgorithm {
    case A128CBCHS256 = "A128CBC-HS256"
    case A256CBCHS512 = "A256CBC-HS512"

    var hmacAlgorithm: HMACAlgorithm {
        switch self {
        case .A256CBCHS512:
            return .SHA512
        case .A128CBCHS256:
            return .SHA256
        }
    }

    public var keyLength: Int {
        switch self {
        case .A256CBCHS512:
            return 64
        case .A128CBCHS256:
            return 32
        }
    }

    public var initializationVectorLength: Int {
        switch self {
        case .A128CBCHS256, .A256CBCHS512:
            return 16
        }
    }

    func checkKeyLength(for key: Data) -> Bool {
        return key.count == keyLength
    }

    public func retrieveKeys(from inputKey: Data) throws -> (hmacKey: Data, encryptionKey: Data) {
        guard checkKeyLength(for: inputKey) else {
            throw JWEError.keyLengthNotSatisfied
        }

        switch self {
        case .A256CBCHS512:
            return (inputKey.subdata(in: 0..<32), inputKey.subdata(in: 32..<64))
        case .A128CBCHS256:
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
    case SHA512 = "SHA512"
    case SHA256 = "SHA256"
    case none = "none"

    var outputLength: Int {
        switch self {
        case .SHA512:
            return 64
        case .SHA256:
            return 32
        case .none:
            return 0
        }
    }
}

/// Algorithm "none" type that should be upsupported for any cryptographic operation.
/// TODO: Perhaps remove if Optionals are enough.
public enum UnsupportedAlgorithm: String, CaseIterable, ContentAlgorithm, KeyAlgorithm {
    case none = "none"
}

/// An algorithm for compressing the plain text before encryption.
/// List of [supported compression algorithms](https://www.iana.org/assignments/jose/jose.xhtml#web-encryption-compression-algorithms)
///
/// - Deflate: [DEF](https://tools.ietf.org/html/rfc7516#section-4.1.3)
public enum CompressionAlgorithm: String {
    case DEFLATE = "DEF"
    case NONE = "NONE"
}
