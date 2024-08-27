//
//  ECKeys.swift
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

// MARK: Protocols

/// The components of an EC public key.
/// See [RFC-7518, Section 6.2.1](https://tools.ietf.org/html/rfc7518#section-6.2.1)
///
/// - Note:
/// To ensure proper JWK JSON encoding, the component data must refer to the unsigned big-endian octet representation
/// of the component's values, encoded using the minimum amount of octets needed to represent the value.
public typealias ECPublicKeyComponents = (
        crv: String,
        x: Data,
        y: Data
)

/// The components of an EC private key.
/// See [RFC-7518, Section 6.2.2](https://tools.ietf.org/html/rfc7518#section-6.2.2)
///
/// - Note:
/// To ensure proper JWK JSON encoding, the component data must refer to the unsigned big-endian octet representation
/// of the component's values, encoded using the minimum amount of octets needed to represent the value.
public typealias ECPrivateKeyComponents = (
        crv: String,
        x: Data,
        y: Data,
        d: Data
)

/// A type that represents an EC public key.
/// It can be expressed through `ECPublicKeyComponents` meaning it can be converted to such components
/// and it can be created from such components.
public protocol ExpressibleAsECPublicKeyComponents {

    /// Creates an object that contains the supplied components in the format specified by ANSI X9.63
    ///
    /// - Parameter components: The public key components.
    /// - Returns: An object containing the supplied components.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    static func representing(ecPublicKeyComponents components: ECPublicKeyComponents) throws -> Self

    /// Extracts the public key components specified by PKCS#1.
    ///
    /// - Returns: The components of the public key.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    func ecPublicKeyComponents() throws -> ECPublicKeyComponents
}

/// A type that represents an EC private key.
/// It can be expressed through `ECPrivateKeyComponents` meaning it can be converted to such components
/// and it can be created from such components.
public protocol ExpressibleAsECPrivateKeyComponents {

    /// Creates an object that contains the supplied components in the format specified by ANSI X9.63
    ///
    /// - Parameter components: The private key components.
    /// - Returns: An object containing the supplied components.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    static func representing(ecPrivateKeyComponents components: ECPrivateKeyComponents) throws -> Self

    /// Extracts the private key components specified by PKCS#1.
    ///
    /// - Returns: The components of the private key.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    func ecPrivateKeyComponents() throws -> ECPrivateKeyComponents
}

// MARK: Public Key

/// A JWK holding an EC public key.
public struct ECPublicKey: JWK {
    /// The JWK key type.
    public let keyType: JWKKeyType

    /// The JWK parameters.
    public let parameters: [String: String]

    /// The EC public key required parameters
    public var requiredParameters: [String: String] {
        [
            JWKParameter.keyType.rawValue: self.keyType.rawValue,
            ECParameter.curve.rawValue: self.crv.rawValue,
            ECParameter.x.rawValue: self.x,
            ECParameter.y.rawValue: self.y
        ]
    }

    /// The curve value for the EC public key.
    public let crv: ECCurveType

    /// The x coordinate value for the EC public key.
    public let x: String

    /// The y coordinate value for the EC public key.
    public let y: String

    /// Initializes a JWK containing an EC public key.
    ///
    /// - Note: Ensure that the x/y coordinates are `base64urlUInt` encoded as described in
    ///         [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    ///
    /// - Parameters:
    ///   - crv: The curve type of the EC public key, as one of the string values specified
    ///        in [RFC-7518, Section 6.2.1.1](https://tools.ietf.org/html/rfc7518#section-6.2.1.1).
    ///   - x: The x coordinate for the EC public key in `base64urlUInt` encoding
    ///        as specified in [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    ///   - y: The y coordinate for the EC public key in `base64urlUInt` encoding
    ///        as specified in [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    ///   - parameters: Additional JWK parameters.
    public init(crv: ECCurveType, x: String, y: String, additionalParameters parameters: [String: String] = [:]) {
        self.keyType = .EC
        self.crv = crv
        self.x = x
        self.y = y

        self.parameters = parameters.merging(
                [
                    JWKParameter.keyType.rawValue: self.keyType.rawValue,
                    ECParameter.curve.rawValue: self.crv.rawValue,
                    ECParameter.x.rawValue: self.x,
                    ECParameter.y.rawValue: self.y
                ],
                uniquingKeysWith: { (_, new) in new }
        )
    }

    /// Creates an `ECPublicKey` JWK with the specified public key and optional additional JWK parameters.
    ///
    /// - Parameters:
    ///   - publicKey: The public key that the resulting JWK should represent.
    ///   - parameters: Any additional parameters to be contained in the JWK.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    public init(publicKey: ExpressibleAsECPublicKeyComponents, additionalParameters parameters: [String: String] = [:]) throws {
        guard let components = try? publicKey.ecPublicKeyComponents() else {
            throw JOSESwiftError.couldNotConstructJWK
        }

        guard let curve = ECCurveType(rawValue: components.crv) else {
            throw JOSESwiftError.invalidCurveType
        }

        // The components are unsigned big-endian integers encoded using the minimum number of octets needed
        // to represent their value as required.
        // Therefore Base64url(component) == Base64urlUInt(component).
        self.init(
                crv: curve,
                x: components.x.base64URLEncodedString(),
                y: components.y.base64URLEncodedString(),
                additionalParameters: parameters
        )
    }

    public init(data: Data) throws {
        self = try JSONDecoder().decode(ECPublicKey.self, from: data)
    }

    /// Converts the `ECPublicKey` JWK to the specified type.
    /// The specified type must conform to the `ExpressibleAsECPublicKeyComponents` protocol.
    ///
    /// **Example:**
    /// `let keyData = try jwk.converted(to: Data.self)`
    ///
    /// - Parameter type: The type to convert the JWK to.
    /// - Returns: The type initialized with the key data.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    public func converted<T>(to type: T.Type) throws -> T where T: ExpressibleAsECPublicKeyComponents {
        guard let x = Data(base64URLEncoded: self.x) else {
            throw JOSESwiftError.xNotBase64URLUIntEncoded
        }

        guard let y = Data(base64URLEncoded: self.y) else {
            throw JOSESwiftError.yNotBase64URLUIntEncoded
        }

        return try T.representing(ecPublicKeyComponents: (self.crv.rawValue, x, y))
    }

    @available(iOS 11.0, *)
    public func withThumbprintAsKeyId(algorithm: JWKThumbprintAlgorithm = .SHA256) throws -> Self {
        let keyId = try thumbprint(algorithm: algorithm)
        return .init(crv: crv, x: x, y: y, additionalParameters: parameters.merging([
            JWKParameter.keyIdentifier.rawValue: keyId
        ], uniquingKeysWith: { (_, new) in new }))
    }
}

// MARK: Private Key

/// A JWK holding an EC private key.
public struct ECPrivateKey: JWK {
    /// The JWK key type.
    public let keyType: JWKKeyType

    /// The JWK parameters.
    public let parameters: [String: String]

    /// The EC private key required parameters
    public var requiredParameters: [String: String] {
        [
            JWKParameter.keyType.rawValue: self.keyType.rawValue,
            ECParameter.curve.rawValue: self.crv.rawValue,
            ECParameter.x.rawValue: self.x,
            ECParameter.y.rawValue: self.y
        ]
    }

    /// The curve value for the EC public key.
    public let crv: ECCurveType

    /// The x coordinate value for the EC public key.
    public let x: String

    /// The y coordinate value for the EC public key.
    public let y: String

    /// The private exponent value for the EC private key.
    public let privateKey: String

    /// Initializes a JWK containing an EC private key.
    ///
    /// - Note: Ensure that the x/y coordinates and private key are `base64urlUInt` encoded as described in
    ///         [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    ///
    /// - Parameters:
    ///   - crv: The curve type of the EC public key, as one of the string values specified
    ///        in [RFC-7518, Section 6.2.1.1](https://tools.ietf.org/html/rfc7518#section-6.2.1.1).
    ///   - x: The x coordinate for the EC public key in `base64urlUInt` encoding
    ///        as specified in [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    ///   - y: The y coordinate for the EC public key in `base64urlUInt` encoding
    ///        as specified in [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    ///   - privateKey: The private key component for the EC public key in `base64urlUInt` encoding
    ///                 as specified in [RFC-7518, Section 2](https://tools.ietf.org/html/rfc7518#section-2).
    ///   - parameters: Additional JWK parameters.
    public init(crv: String, x: String, y: String, privateKey: String, additionalParameters parameters: [String: String] = [:]) throws {
        self.keyType = .EC

        guard let curve = ECCurveType(rawValue: crv) else {
            throw JOSESwiftError.invalidCurvePointOctetLength
        }

        self.crv = curve
        self.x = x
        self.y = y
        self.privateKey = privateKey

        self.parameters = parameters.merging(
                [
                    JWKParameter.keyType.rawValue: self.keyType.rawValue,
                    ECParameter.curve.rawValue: self.crv.rawValue,
                    ECParameter.x.rawValue: self.x,
                    ECParameter.y.rawValue: self.y,
                    ECParameter.privateKey.rawValue: self.privateKey
                ],
                uniquingKeysWith: { (_, new) in new }
        )
    }

    /// Creates an `ECPrivateKey` JWK with the specified private key and optional additional JWK parameters.
    ///
    /// - Parameters:
    ///   - privateKey: The private key that the resulting JWK should represent.
    ///   - parameters: Any additional parameters to be contained in the JWK.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    public init(privateKey: ExpressibleAsECPrivateKeyComponents, additionalParameters parameters: [String: String] = [:]) throws {
        guard let (crv, x, y, privateKey) = try? privateKey.ecPrivateKeyComponents() else {
            throw JOSESwiftError.couldNotConstructJWK
        }

        // The components are unsigned big-endian integers encoded using the minimum number of octets needed
        // to represent their value as required.
        // Therefore Base64url(component) == Base64urlUInt(component).
        try self.init(
                crv: crv,
                x: x.base64URLEncodedString(),
                y: y.base64URLEncodedString(),
                privateKey: privateKey.base64URLEncodedString(),
                additionalParameters: parameters
        )
    }

    public init(data: Data) throws {
        self = try JSONDecoder().decode(ECPrivateKey.self, from: data)
    }

    /// Converts the `ECPrivateKey` JWK to the specified type.
    /// The specified type must conform to the `ExpressibleAsECPrivateKeyComponents` protocol.
    ///
    /// **Example:**
    /// `let keyData = try jwk.converted(to: Data.self)`
    ///
    /// - Parameter type: The type to convert the JWK to.
    /// - Returns: The type initialized with the key data.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    public func converted<T>(to type: T.Type) throws -> T where T: ExpressibleAsECPrivateKeyComponents {
        guard let x = Data(base64URLEncoded: self.x) else {
            throw JOSESwiftError.xNotBase64URLUIntEncoded
        }

        guard let y = Data(base64URLEncoded: self.y) else {
            throw JOSESwiftError.yNotBase64URLUIntEncoded
        }

        guard let privateKey = Data(base64URLEncoded: self.privateKey) else {
            throw JOSESwiftError.privateKeyNotBase64URLUIntEncoded
        }

        return try T.representing(ecPrivateKeyComponents: (self.crv.rawValue, x, y, privateKey))
    }

    @available(iOS 11.0, *)
    public func withThumbprintAsKeyId(algorithm: JWKThumbprintAlgorithm = .SHA256) throws -> Self {
        let keyId = try thumbprint(algorithm: algorithm)
        return try .init(crv: crv.rawValue, x: x, y: y, privateKey: privateKey, additionalParameters: parameters.merging([
            JWKParameter.keyIdentifier.rawValue: keyId
        ], uniquingKeysWith: { (_, new) in new }))
    }
}

// MARK: Key Pair

public typealias ECKeyPair = ECPrivateKey
