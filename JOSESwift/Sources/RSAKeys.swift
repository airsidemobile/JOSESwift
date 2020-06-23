//
//  RSAKeys.swift
//  JOSESwift
//
//  Created by Daniel Egger on 14.12.17.
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

/// A type that represents an RSA public key.
/// It can be expressed through `RSAPublicKeyComponents` meaning it can be converted to such components
/// and it can be created from such components.
public protocol ExpressibleAsRSAPublicKeyComponents {

    /// Creates an object that contains the supplied components in the format specified by PKCS#1.
    ///
    /// - Parameter components: The public key components.
    /// - Returns: An object containing the supplied components.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    static func representing(rsaPublicKeyComponents components: RSAPublicKeyComponents) throws -> Self

    /// Extracts the public key components specified by PKCS#1.
    ///
    /// - Returns: The components of the public key.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    func rsaPublicKeyComponents() throws -> RSAPublicKeyComponents
}

/// A type that represents an RSA private key.
/// It can be expressed through `RSAPrivateKeyComponents` meaning it can be converted to such components
/// and it can be created from such components.
public protocol ExpressibleAsRSAPrivateKeyComponents {

    /// Creates an object that contains the supplied components in the format specified by PKCS#1.
    ///
    /// - Parameter components: The private key components.
    /// - Returns: An object containing the supplied components.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    static func representing(rsaPrivateKeyComponents components: RSAPrivateKeyComponents) throws -> Self

    /// Extracts the private key components specified by PKCS#1.
    ///
    /// - Returns: The components of the private key.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    func rsaPrivateKeyComponents() throws -> RSAPrivateKeyComponents
}

// MARK: Public Key

/// A JWK holding an RSA pubkic key.
public struct RSAPublicKey: JWK {
    /// The JWK key type.
    public let keyType: JWKKeyType

    /// The JWK parameters.
    public let parameters: [String: String]

    /// The RSA required parameters
    public var requiredParameters: [String: String] {
        [
            JWKParameter.keyType.rawValue: self.keyType.rawValue,
            RSAParameter.modulus.rawValue: self.modulus,
            RSAParameter.exponent.rawValue: self.exponent
        ]
    }

    /// The modulus value for the RSA public key.
    public let modulus: String

    /// The exponent value for the RSA public key.
    public let exponent: String

    /// Initializes a JWK containing an RSA public key.
    ///
    /// - Note: Ensure that the modulus and exponent are `base64urlUInt` encoded as described in
    ///         [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
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

    /// Creates an `RSAPublicKey` JWK with the specified public key and optional additional JWK parameters.
    ///
    /// - Parameters:
    ///   - publicKey: The public key that the resulting JWK should represent.
    ///   - parameters: Any additional parameters to be contained in the JWK.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    public init(publicKey: ExpressibleAsRSAPublicKeyComponents, additionalParameters parameters: [String: String] = [:]) throws {
        guard let components = try? publicKey.rsaPublicKeyComponents() else {
            throw JOSESwiftError.couldNotConstructJWK
        }

        // The components are unsigned big-endian integers encoded using the minimum number of octets needed
        // to represent their value as required.
        // Therefore Base64url(component) == Base64urlUInt(component).
        self.init(
            modulus: components.modulus.base64URLEncodedString(),
            exponent: components.exponent.base64URLEncodedString(),
            additionalParameters: parameters
        )
    }

    /// Creates an `RSAPublicKey` from the JSON representation of a public key JWK.
    public init(data: Data) throws {
        self = try JSONDecoder().decode(RSAPublicKey.self, from: data)
    }

    /// Converts the `RSAPublicKey` JWK to the specified type.
    /// The specified type must conform to the `ExpressibleAsRSAPublicKeyComponents` protocol.
    ///
    /// **Example:**
    /// `let keyData = try jwk.converted(to: Data.self)`
    ///
    /// - Parameter type: The type to convert the JWK to.
    /// - Returns: The type initialized with the key data.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    public func converted<T>(to type: T.Type) throws -> T where T: ExpressibleAsRSAPublicKeyComponents {
        guard let modulusData = Data(base64URLEncoded: self.modulus) else {
            throw JOSESwiftError.modulusNotBase64URLUIntEncoded
        }

        guard let exponentData = Data(base64URLEncoded: self.exponent) else {
            throw JOSESwiftError.exponentNotBase64URLUIntEncoded
        }

        return try T.representing(rsaPublicKeyComponents: (modulusData, exponentData))
    }

    @available(iOS 11.0, *)
    public func withThumbprintAsKeyId(algorithm: JWKThumbprintAlgorithm = .SHA256) throws -> Self {
        let keyId = try thumbprint(algorithm: algorithm)
        return .init(modulus: modulus, exponent: exponent, additionalParameters: parameters.merging([
            JWKParameter.keyIdentifier.rawValue: keyId
        ], uniquingKeysWith: { (_, new) in new }))
    }
}

// MARK: Private Key

/// A JWK holding an RSA private key.
public struct RSAPrivateKey: JWK {
    /// The JWK key type.
    public let keyType: JWKKeyType

    /// The JWK parameters.
    public let parameters: [String: String]

    /// The RSA required parameters
    public var requiredParameters: [String: String] {
        [
            JWKParameter.keyType.rawValue: self.keyType.rawValue,
            RSAParameter.modulus.rawValue: self.modulus,
            RSAParameter.exponent.rawValue: self.exponent
        ]
    }

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

    /// Creates an `RSAPrivateKey` JWK with the specified private key and optional additional JWK parameters.
    ///
    /// - Parameters:
    ///   - privateKey: The private key that the resulting JWK should represent.
    ///   - parameters: Any additional parameters to be contained in the JWK.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    public init(privateKey: ExpressibleAsRSAPrivateKeyComponents, additionalParameters parameters: [String: String] = [:]) throws {
        guard let (modulus, exponent, privateExponent) = try? privateKey.rsaPrivateKeyComponents() else {
            throw JOSESwiftError.couldNotConstructJWK
        }

        // The components are unsigned big-endian integers encoded using the minimum number of octets needed
        // to represent their value as required.
        // Therefore Base64url(component) == Base64urlUInt(component).
        self.init(
            modulus: modulus.base64URLEncodedString(),
            exponent: exponent.base64URLEncodedString(),
            privateExponent: privateExponent.base64URLEncodedString(),
            additionalParameters: parameters
        )
    }

    /// Creates an `RSAPrivateKey` from the JSON representation of a private key JWK.
    public init(data: Data) throws {
        self = try JSONDecoder().decode(RSAPrivateKey.self, from: data)
    }

    /// Converts the `RSAPrivateKey` JWK to the specified type.
    /// The specified type must conform to the `ExpressibleAsRSAPrivateKeyComponents` protocol.
    ///
    /// **Example:**
    /// `let keyData = try jwk.converted(to: Data.self)`
    ///
    /// - Parameter type: The type to convert the JWK to.
    /// - Returns: The type initialized with the key data.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    public func converted<T>(to type: T.Type) throws -> T where T: ExpressibleAsRSAPrivateKeyComponents {
        guard let modulusData = Data(base64URLEncoded: self.modulus) else {
            throw JOSESwiftError.modulusNotBase64URLUIntEncoded
        }

        guard let exponentData = Data(base64Encoded: self.exponent) else {
            throw JOSESwiftError.exponentNotBase64URLUIntEncoded
        }

        guard let privateExponentData = Data(base64Encoded: self.exponent) else {
            throw JOSESwiftError.privateExponentNotBase64URLUIntEncoded
        }

        return try T.representing(rsaPrivateKeyComponents: (modulusData, exponentData, privateExponentData))
    }

    @available(iOS 11.0, *)
    public func withThumbprintAsKeyId(algorithm: JWKThumbprintAlgorithm = .SHA256) throws -> Self {
        let keyId = try thumbprint(algorithm: algorithm)
        return .init(modulus: modulus, exponent: exponent, privateExponent: privateExponent, additionalParameters: parameters.merging([
            JWKParameter.keyIdentifier.rawValue: keyId
        ], uniquingKeysWith: { (_, new) in new }))
    }
}

// MARK: Key Pair

public typealias RSAKeyPair = RSAPrivateKey
