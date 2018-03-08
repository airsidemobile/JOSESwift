//
//  JWKSetCodable.swift
//  JOSESwift
//
//  Created by Daniel Egger on 15.02.18.
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

enum JWKSetParameter: String, CodingKey {
    case keys
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
            var key: JWK?

            do {
                key = try keyContainer.decode(RSAPrivateKey.self)
            } catch DecodingError.keyNotFound(RSAParameter.privateExponent, _) {
                key = try keyContainer.decode(RSAPublicKey.self)
            }

            guard let rsaKey = key else {
                throw DecodingError.dataCorruptedError(in: keyContainer, debugDescription: """
                    No RSAPublicKey or RSAPrivateKey found to decode.
                    """
                )
            }

            keys.append(rsaKey)
        }

        self.init(keys: keys)
    }
}
