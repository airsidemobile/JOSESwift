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

fileprivate enum RSAParameterName: String {
    case modulus = "n"
    case exponent = "e"
    case privateExponent = "d"
}

// MARK: Public Key

/// A JWK holding an RSA pubkic key.
public struct RSAPublicKey: JWK {
    /// The JWK key type.
    public let keyType: JWKKeyType

    /// The JWK parameters.
    public let parameters: [String: Any]

    /// The modulus value for the RSA public key.
    public let modulus: String

    /// The exponent value for the RSA public key.
    public let exponent: String

    /// Initializes a JWK containing an RSA public key.
    ///
    /// - Parameters:
    ///   - modulus: The modulus value for the RSA public key.
    ///   - exponent: The exponent value for the RSA public key.
    ///   - parameters: Additional JWK parameters.
    public init(modulus: String, exponent: String, additionalParameters parameters: [String: Any] = [:]) {
        self.keyType = .RSA
        self.modulus = modulus
        self.exponent = exponent

        self.parameters = parameters.merging(
            [
                JWKKeyType.parameterName: self.keyType.rawValue,
                RSAParameterName.modulus.rawValue: self.modulus,
                RSAParameterName.exponent.rawValue: self.exponent
            ],
            uniquingKeysWith: { (_, new) in new }
        )
    }

    /// Initializes a JWK containing an RSA public key.
    ///
    /// - Parameter parameters: The JWK parameters.
    /// - Throws: `JWKError` if the provided parameters are incomplete.
    public init(parameters: [String: Any]) throws {
        let modulus = try parameters.get(.modulus)
        let exponent = try parameters.get(.exponent)

        self.init(modulus: modulus, exponent: exponent, additionalParameters: parameters)
    }
}

// MARK: Privat Key

/// A JWK holding an RSA private key.
public struct RSAPrivateKey: JWK {
    /// The JWK key type.
    public let keyType: JWKKeyType

    /// The JWK parameters.
    public let parameters: [String: Any]

    /// The modulus value for the RSA private key.
    public let modulus: String

    /// The exponent value for the RSA private key.
    public let exponent: String

    /// The private exponent value for the RSA private key.
    public let privateExponent: String

    /// Initializes a JWK containing an RSA private key.
    ///
    /// - Parameters:
    ///   - modulus: The modulus value for the RSA private key.
    ///   - exponent: The exponent value for the RSA private key.
    //    - privateExponent: The private exponent value for the RSA private key.
    ///   - parameters: Additional JWK parameters.
    public init(modulus: String, exponent: String, privateExponent: String, additionalParameters parameters: [String: Any] = [:]) {
        self.keyType = .RSA
        self.modulus = modulus
        self.exponent = exponent
        self.privateExponent = privateExponent

        self.parameters = parameters.merging(
            [
                JWKKeyType.parameterName: self.keyType.rawValue,
                RSAParameterName.modulus.rawValue: self.modulus,
                RSAParameterName.exponent.rawValue: self.exponent,
                RSAParameterName.privateExponent.rawValue: self.privateExponent
            ],
            uniquingKeysWith: { (_, new) in new }
        )
    }

    /// Initializes a JWK containing an RSA private key.
    ///
    /// - Parameter parameters: The JWK parameters.
    /// - Throws: `JWKError` if the provided parameters are incomplete.
    public init(parameters: [String: Any]) throws {
        let modulus = try parameters.get(.modulus)
        let exponent = try parameters.get(.exponent)
        let privateExponent = try parameters.get(.privateExponent)

        self.init(modulus: modulus, exponent: exponent, privateExponent: privateExponent, additionalParameters: parameters)
    }
}

// MARK: Key Pair

public typealias RSAKeyPair = RSAPrivateKey

// MARK: - Parsing

fileprivate extension Dictionary where Key == String, Value == Any {
    func get(_ parameterName: RSAParameterName) throws -> String {
        guard let parameter = self[parameterName.rawValue] as? String else {
            throw JWKError.requiredRSAParameterMissing(parameter: parameterName.rawValue)
        }

        return parameter
    }
}

internal extension JWKParser {
    func parseRSA(from parameters: [String: Any]) throws -> JWK {
        do {
            return try RSAPrivateKey(parameters: parameters)
        } catch JWKError.requiredRSAParameterMissing(let parameter) where parameter == RSAParameterName.privateExponent.rawValue {
            return try RSAPublicKey(parameters: parameters)
        }
    }
}
