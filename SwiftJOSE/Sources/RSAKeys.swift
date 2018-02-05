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

internal enum RSAKeyParameter: String, CodingKey {
    case modulus = "n"
    case exponent = "e"
    case privateExponent = "d"
}

// MARK: Convertibles

public protocol RSAPublicKeyConvertible {
    var modulus: Data? { get }
    var exponent: Data? { get }
}

public protocol RSAPrivateKeyConvertible: RSAPublicKeyConvertible {
    var privateExponent: Data? { get }
}

// MARK: Public Key

/// A JWK holding an RSA pubkic key.
public struct RSAPublicKey: JWK {
    /// The JWK key type.
    public let keyType: JWKKeyType

    /// The JWK parameters.
    public let parameters: [String: String]

    /// The modulus value for the RSA public key.
    public let modulus: String

    /// The exponent value for the RSA public key.
    public let exponent: String

    /// Initializes a JWK containing an RSA public key.
    ///
    /// - Parameters:
    ///   - modulus: The modulus value for the RSA public key in `base64urlUInt` encoding
    ///              as specified in [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    ///   - exponent: The public exponent value for the RSA public key in `base64urlUInt` encoding
    ///               as specified in [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    ///   - parameters: Additional JWK parameters.
    public init(modulus: String, exponent: String, additionalParameters parameters: [String: String] = [:]) {
        self.keyType = .RSA
        self.modulus = modulus
        self.exponent = exponent

        self.parameters = parameters.merging(
            [
                JWKParameter.keyType.rawValue: self.keyType.rawValue,
                RSAKeyParameter.modulus.rawValue: self.modulus,
                RSAKeyParameter.exponent.rawValue: self.exponent
            ],
            uniquingKeysWith: { (_, new) in new }
        )
    }

    public init(publicKey: RSAPublicKeyConvertible, additionalParameters parameters: [String: String] = [:]) throws {
        guard let modulus = publicKey.modulus else {
            throw JWKError.cannotExtractRSAModulus
        }

        guard let exponent = publicKey.exponent else {
            throw JWKError.cannotExtractRSAPublicExponent
        }

        // Todo: Base64urlUInt?
        self.init(
            modulus: modulus.base64URLEncodedString(),
            exponent: exponent.base64URLEncodedString(),
            additionalParameters: parameters
        )
    }
}

// MARK: Private Key

/// A JWK holding an RSA private key.
public struct RSAPrivateKey: JWK {
    /// The JWK key type.
    public let keyType: JWKKeyType

    /// The JWK parameters.
    public let parameters: [String: String]

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
    public init(modulus: String, exponent: String, privateExponent: String, additionalParameters parameters: [String: String] = [:]) {
        self.keyType = .RSA
        self.modulus = modulus
        self.exponent = exponent
        self.privateExponent = privateExponent

        self.parameters = parameters.merging(
            [
                JWKParameter.keyType.rawValue: self.keyType.rawValue,
                RSAKeyParameter.modulus.rawValue: self.modulus,
                RSAKeyParameter.exponent.rawValue: self.exponent,
                RSAKeyParameter.privateExponent.rawValue: self.privateExponent
            ],
            uniquingKeysWith: { (_, new) in new }
        )
    }

    public init(privateKey: RSAPrivateKeyConvertible, additionalParameters parameters: [String: String] = [:]) throws {
        guard let modulus = privateKey.modulus else {
            throw JWKError.cannotExtractRSAModulus
        }

        guard let exponent = privateKey.exponent else {
            throw JWKError.cannotExtractRSAPublicExponent
        }

        guard let privateExponent = privateKey.privateExponent else {
            throw JWKError.cannotExtractRSAPrivateExponent
        }

        // Todo: Base64urlUInt?
        self.init(
            modulus: modulus.base64URLEncodedString(),
            exponent: exponent.base64URLEncodedString(),
            privateExponent: privateExponent.base64URLEncodedString(),
            additionalParameters: parameters
        )
    }
}

// MARK: Key Pair

public typealias RSAKeyPair = RSAPrivateKey
