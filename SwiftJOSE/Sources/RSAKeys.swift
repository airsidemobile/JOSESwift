//
//  RSAKeys.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
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

fileprivate enum ParameterName: String {
    case modulus = "n"
    case exponent = "e"
    case privateExponent = "d"
}

fileprivate extension Dictionary where Key == String, Value == Any {
    func get(_ parameterName: ParameterName) throws -> String {
        guard let parameter = self[parameterName.rawValue] as? String else {
            throw JWKError.RequiredRSAParameterMissing(parameter: parameterName.rawValue)
        }

        return parameter
    }
}

internal extension JWKParser {
    func parseRSA(from parameters: [String: Any]) throws -> JWK {
        do {
            return try RSAPrivateKey(parameters: parameters)
        } catch JWKError.RequiredRSAParameterMissing(let parameter) where parameter == ParameterName.privateExponent.rawValue {
            return try RSAPublicKey(parameters: parameters)
        }
    }
}

public struct RSAPublicKey: JWK {
    public let keyType: JWKKeyType
    public let parameters: [String: Any]

    public let modulus: String
    public let exponent: String

    public init(modulus: String, exponent: String, additionalParameters parameters: [String: Any] = [:]) {
        self.keyType = .RSA
        self.modulus = modulus
        self.exponent = exponent

        self.parameters = parameters.merging(
            [
                JWKKeyType.parameterName: self.keyType.rawValue,
                ParameterName.modulus.rawValue: self.modulus,
                ParameterName.exponent.rawValue: self.exponent
            ],
            uniquingKeysWith: { (_, new) in new }
        )
    }

    public init(parameters: [String: Any]) throws {
        let modulus = try parameters.get(.modulus)
        let exponent = try parameters.get(.exponent)

        self.init(modulus: modulus, exponent: exponent, additionalParameters: parameters)
    }
}

public struct RSAPrivateKey: JWK {
    public let keyType: JWKKeyType
    public let parameters: [String: Any]

    public let modulus: String
    public let exponent: String
    public let privateExponent: String

    public init(modulus: String, exponent: String, privateExponent: String, additionalParameters parameters: [String: Any] = [:]) {
        self.keyType = .RSA
        self.modulus = modulus
        self.exponent = exponent
        self.privateExponent = privateExponent

        self.parameters = parameters.merging(
            [
                JWKKeyType.parameterName: self.keyType.rawValue,
                ParameterName.modulus.rawValue: self.modulus,
                ParameterName.exponent.rawValue: self.exponent,
                ParameterName.privateExponent.rawValue: self.privateExponent
            ],
            uniquingKeysWith: { (_, new) in new }
        )
    }

    public init(parameters: [String: Any]) throws {
        let modulus = try parameters.get(.modulus)
        let exponent = try parameters.get(.exponent)
        let privateExponent = try parameters.get(.privateExponent)

        self.init(modulus: modulus, exponent: exponent, privateExponent: privateExponent, additionalParameters: parameters)
    }
}

public typealias RSAKeyPair = RSAPrivateKey
