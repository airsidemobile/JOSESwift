//
//  JWKSetCodable.swift
//  JOSESwift
//
//  Created by Daniel Egger on 15.02.18.
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

enum JWKSetParameter: String, CodingKey {
    case keys
}

internal enum JWKBaseParameter: String, CodingKey {
    case kty
    case d
}

internal enum JWKTypeError: Error {
    case typeIsECPrivate
    case typeIsECPublic
    case typeIsRSAPublic
    case typeIsRSAPrivate
    case typeIsSymmetric
    case typeIsUnknown
}

class JWKBase: Decodable {
    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: JWKBaseParameter.self)
        let key = try container.decode(String.self, forKey: .kty)
        let d = try? container.decode(String.self, forKey: .d)
        switch key {
        case JWKKeyType.RSA.rawValue:
            if d == nil {
                throw JWKTypeError.typeIsRSAPublic
            } else {
                throw JWKTypeError.typeIsRSAPrivate
            }
        case JWKKeyType.OCT.rawValue:
            throw JWKTypeError.typeIsSymmetric
        case JWKKeyType.EC.rawValue:
            if d == nil {
                throw JWKTypeError.typeIsECPublic
            } else {
                throw JWKTypeError.typeIsECPrivate
            }
        default:
            throw JWKTypeError.typeIsUnknown
        }
    }
}

extension JWKSet: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: JWKSetParameter.self)
        var keyContainer = container.nestedUnkeyedContainer(forKey: .keys)

        for key in self.keys {
            switch key {
            case is RSAPublicKey:
                // swiftlint:disable:next force_cast
                try keyContainer.encode(key as! RSAPublicKey)
            case is RSAPrivateKey:
                // swiftlint:disable:next force_cast
                try keyContainer.encode(key as! RSAPrivateKey)
            case is SymmetricKey:
                // swiftlint:disable:next force_cast
                try keyContainer.encode(key as! SymmetricKey)
            case is ECPublicKey:
                // swiftlint:disable:next force_cast
                try keyContainer.encode(key as! ECPublicKey)
            case is ECPrivateKey:
                // swiftlint:disable:next force_cast
                try keyContainer.encode(key as! ECPrivateKey)
            default:
                break
            }
        }
    }
}

extension JWKSet: Decodable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: JWKSetParameter.self)
        var keyContainer = try container.nestedUnkeyedContainer(forKey: .keys)

        var keys: [JWK] = []
        while !keyContainer.isAtEnd {

            var maybeKey: JWK?

            do {
                _ = try keyContainer.decode(JWKBase.self)
            } catch JWKTypeError.typeIsECPublic {
                maybeKey = try? keyContainer.decode(ECPublicKey.self)
            } catch JWKTypeError.typeIsECPrivate {
                maybeKey = try? keyContainer.decode(ECPrivateKey.self)
            } catch JWKTypeError.typeIsRSAPublic {
                maybeKey = try? keyContainer.decode(RSAPublicKey.self)
            } catch JWKTypeError.typeIsRSAPrivate {
                maybeKey = try? keyContainer.decode(RSAPrivateKey.self)
            } catch JWKTypeError.typeIsSymmetric {
                maybeKey = try? keyContainer.decode(SymmetricKey.self)
            } catch {
                let description =
                    """
                    No valid RSAPrivateKey, RSAPublicKey, SymmetricKey, ECPrivateKey, or ECPublicKey
                    JSON found to decode.
                    """
                throw DecodingError.dataCorruptedError(in: keyContainer, debugDescription: description)
            }

            guard let key = maybeKey else {
                let description =
                    """
                    No RSAPrivateKey, RSAPublicKey, SymmetricKey, ECPrivateKey, or ECPublicKey found to decode.
                    """
                throw DecodingError.dataCorruptedError(in: keyContainer, debugDescription: description)
            }

            keys.append(key)
        }

        self.init(keys: keys)
    }
}
