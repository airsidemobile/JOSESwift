//
//  ECKeyCodable.swift
//  JOSESwift
//
//  Created by Jarrod Moldrich on 02.07.18.
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

extension ECPublicKey: Encodable {
    public func encode(to encoder: Encoder) throws {
        var commonParameters = encoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        try commonParameters.encode(keyType, forKey: .keyType)

        // Other common parameters are optional.
        for parameter in parameters {
            // Only encode known parameters.
            if let key = JWKParameter(rawValue: parameter.key) {
                try commonParameters.encode(parameter.value, forKey: key)
            }
        }

        // EC public key specific parameters.
        var ecParameters = encoder.container(keyedBy: ECParameter.self)
        try ecParameters.encode(crv, forKey: .curve)
        try ecParameters.encode(x, forKey: .x)
        try ecParameters.encode(y, forKey: .y)
    }
}

extension ECPublicKey: Decodable {
    public init(from decoder: Decoder) throws {
        let commonParameters = try decoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        guard try commonParameters.decode(String.self, forKey: .keyType) == JWKKeyType.EC.rawValue else {
            throw DecodingError.keyNotFound(
                    JWKParameter.keyType,
                    DecodingError.Context.init(
                            codingPath: [JWKParameter.keyType],
                            debugDescription: "Key Type parameter wrong."
                    )
            )
        }

        // Other common parameters are optional.
        var parameters: [String: String] = [:]
        for key in commonParameters.allKeys where !JWKParameter.nonStringParameters.contains(key) {
            parameters[key.rawValue] = try commonParameters.decode(String.self, forKey: key)
        }

        // EC public key specific parameters.
        let ecParameters = try decoder.container(keyedBy: ECParameter.self)
        let crv = try ecParameters.decode(ECCurveType.self, forKey: .curve)
        let x = try ecParameters.decode(String.self, forKey: .x)
        let y = try ecParameters.decode(String.self, forKey: .y)

        self.init(
                crv: crv,
                x: x,
                y: y,
                additionalParameters: parameters
        )
    }
}

extension ECPrivateKey: Encodable {
    public func encode(to encoder: Encoder) throws {
        var commonParameters = encoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        try commonParameters.encode(keyType, forKey: .keyType)

        // Other common parameters are optional.
        for parameter in parameters {
            // Only encode known parameters.
            if let key = JWKParameter(rawValue: parameter.key) {
                try commonParameters.encode(parameter.value, forKey: key)
            }
        }

        // EC private key specific parameters.
        var ecParameters = encoder.container(keyedBy: ECParameter.self)
        try ecParameters.encode(crv, forKey: .curve)
        try ecParameters.encode(x, forKey: .x)
        try ecParameters.encode(y, forKey: .y)
        try ecParameters.encode(privateKey, forKey: .privateKey)
    }
}

extension ECPrivateKey: Decodable {
    public init(from decoder: Decoder) throws {
        let commonParameters = try decoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        guard try commonParameters.decode(String.self, forKey: .keyType) == JWKKeyType.EC.rawValue else {
            throw DecodingError.keyNotFound(
                    JWKParameter.keyType,
                    DecodingError.Context.init(
                            codingPath: [JWKParameter.keyType],
                            debugDescription: "Key Type parameter wrong."
                    )
            )
        }

        // Other common parameters are optional.
        var parameters: [String: String] = [:]
        for key in commonParameters.allKeys where !JWKParameter.nonStringParameters.contains(key) {
            parameters[key.rawValue] = try commonParameters.decode(String.self, forKey: key)
        }

        // EC private key specific parameters.
        let ecParameters = try decoder.container(keyedBy: ECParameter.self)
        let crv = try ecParameters.decode(ECCurveType.self, forKey: .curve)
        let x = try ecParameters.decode(String.self, forKey: .x)
        let y = try ecParameters.decode(String.self, forKey: .y)
        let privateKey = try ecParameters.decode(String.self, forKey: .privateKey)

        try self.init(
                crv: crv.rawValue,
                x: x,
                y: y,
                privateKey: privateKey,
                additionalParameters: parameters
        )
    }
}
