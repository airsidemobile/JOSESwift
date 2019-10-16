//
//  RSAKeyCodable.swift
//  JOSESwift
//
//  Created by Daniel Egger on 05.02.18.
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

extension RSAPublicKey: Encodable {
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

        // RSA public key specific parameters.
        var rsaParameters = encoder.container(keyedBy: RSAParameter.self)
        try rsaParameters.encode(modulus, forKey: .modulus)
        try rsaParameters.encode(exponent, forKey: .exponent)
    }
}

extension RSAPublicKey: Decodable {
    public init(from decoder: Decoder) throws {
        let commonParameters = try decoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        guard try commonParameters.decode(String.self, forKey: .keyType) == JWKKeyType.RSA.rawValue else {
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

        // RSA public key specific parameters.
        let rsaParameters = try decoder.container(keyedBy: RSAParameter.self)
        let modulus = try rsaParameters.decode(String.self, forKey: .modulus)
        let exponent = try rsaParameters.decode(String.self, forKey: .exponent)

        self.init(
            modulus: modulus,
            exponent: exponent,
            additionalParameters: parameters
        )
    }
}

extension RSAPrivateKey: Encodable {
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

        // RSA private key specific parameters.
        var rsaParameters = encoder.container(keyedBy: RSAParameter.self)
        try rsaParameters.encode(modulus, forKey: .modulus)
        try rsaParameters.encode(exponent, forKey: .exponent)
        try rsaParameters.encode(privateExponent, forKey: .privateExponent)
    }
}

extension RSAPrivateKey: Decodable {
    public init(from decoder: Decoder) throws {
        let commonParameters = try decoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        guard try commonParameters.decode(String.self, forKey: .keyType) == JWKKeyType.RSA.rawValue else {
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

        // RSA private key specific parameters.
        let rsaParameters = try decoder.container(keyedBy: RSAParameter.self)
        let modulus = try rsaParameters.decode(String.self, forKey: .modulus)
        let exponent = try rsaParameters.decode(String.self, forKey: .exponent)
        let privateExponent = try rsaParameters.decode(String.self, forKey: .privateExponent)

        self.init(
            modulus: modulus,
            exponent: exponent,
            privateExponent: privateExponent,
            additionalParameters: parameters
        )
    }
}
