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

// MARK: Protocols

/// The components of an RSA public key.
/// See [RFC-3447, Section 3.1](https://tools.ietf.org/html/rfc3447#section-3.1).
///
/// - Note:
/// To ensure proper JWK JSON encoding, the component data must refer to the unsigned big-endian octet representation
/// of the component's values, encoded using the minimum amount of octets needed to represent the value.
public typealias RSAPublicKeyComponents = (
    modulus: Data,
    exponent: Data
)

/// The components of an RSA private key.
/// See [RFC-3447, Section 3.2](https://tools.ietf.org/html/rfc3447#section-3.2).
///
/// - Note:
/// To ensure proper JWK JSON encoding, the component data must refer to the unsigned big-endian octet representation
/// of the component's values, encoded using the minimum amount of octets needed to represent the value.
public typealias RSAPrivateKeyComponents = (
    modulus: Data,
    exponent: Data,
    privateExponent: Data
)

/// A type that can be converted to an `RSAPublicKey` JWK through
/// its RSA public key components.
public protocol ExpressibleAsRSAPublicKeyComponents {
    static func converted(from components: RSAPublicKeyComponents) throws -> Self
    func rsaPublicKeyComponents() throws -> RSAPublicKeyComponents
}

/// A type that can be converted to an `RSAPrivateKey` JWK through
/// its RSA private key components.
public protocol ExpressibleAsRSAPrivateKeyComponents {
    func rsaPrivateKeyComponents() throws -> RSAPrivateKeyComponents
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
                RSAParameter.modulus.rawValue: self.modulus,
                RSAParameter.exponent.rawValue: self.exponent
            ],
            uniquingKeysWith: { (_, new) in new }
        )
    }

    public init(publicKey: ExpressibleAsRSAPublicKeyComponents, additionalParameters parameters: [String: String] = [:]) throws {
        guard let components = try? publicKey.rsaPublicKeyComponents() else {
            throw JWKError.cannotExtractRSAPublicKeyComponents
        }

        // The components are unsigned big-enidan integers encoded using the minimum number of octets needed
        // to represent their value as required.
        // Therefore Base64url(component) == Base64urlUInt(component).
        self.init(
            modulus: components.modulus.base64URLEncodedString(),
            exponent: components.exponent.base64URLEncodedString(),
            additionalParameters: parameters
        )
    }
    
    public init(data: Data) throws {
        self = try JSONDecoder().decode(RSAPublicKey.self, from: data)
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
    ///   - modulus: The modulus value for the RSA private key in `base64urlUInt` encoding
    ///              as specified in [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    ///   - exponent: The exponent value for the RSA private key in `base64urlUInt` encoding
    ///               as specified in [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    //    - privateExponent: The private exponent value for the RSA private key in `base64urlUInt` encoding
    ///               as specified in [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    ///   - parameters: Additional JWK parameters.
    public init(modulus: String, exponent: String, privateExponent: String, additionalParameters parameters: [String: String] = [:]) {
        self.keyType = .RSA
        self.modulus = modulus
        self.exponent = exponent
        self.privateExponent = privateExponent

        self.parameters = parameters.merging(
            [
                JWKParameter.keyType.rawValue: self.keyType.rawValue,
                RSAParameter.modulus.rawValue: self.modulus,
                RSAParameter.exponent.rawValue: self.exponent,
                RSAParameter.privateExponent.rawValue: self.privateExponent
            ],
            uniquingKeysWith: { (_, new) in new }
        )
    }

    public init(privateKey: ExpressibleAsRSAPrivateKeyComponents, additionalParameters parameters: [String: String] = [:]) throws {
        guard let (modulus, exponent, privateExponent) = try? privateKey.rsaPrivateKeyComponents() else {
            throw JWKError.cannotExtractRSAPrivateKeyComponents
        }

        // The components are unsigned big-enidan integers encoded using the minimum number of octets needed
        // to represent their value as required.
        // Therefore Base64url(component) == Base64urlUInt(component).
        self.init(
            modulus: modulus.base64URLEncodedString(),
            exponent: exponent.base64URLEncodedString(),
            privateExponent: privateExponent.base64URLEncodedString(),
            additionalParameters: parameters
        )
    }

    public init(data: Data) throws {
        self = try JSONDecoder().decode(RSAPrivateKey.self, from: data)
    }
}

// MARK: Key Pair

public typealias RSAKeyPair = RSAPrivateKey
