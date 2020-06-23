//
//  SymmetricKeys.swift
//  JOSESwift
//
//  Created by Daniel Egger on 10.07.18.
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

/// The components of a symmetric key.
public typealias SymmetricKeyComponents = (
    Data
)

/// A type that represents a symmetric key.
/// It can be expressed through `SymmetricKeyComponents` meaning it can be converted to such components
/// and it can be created from such components.
public protocol ExpressibleAsSymmetricKeyComponents {

    /// Creates an object that contains the supplied components.
    ///
    /// - Parameter components: The symmetric key components.
    /// - Returns: An object containing the supplied components.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    static func representing(symmetricKeyComponents components: SymmetricKeyComponents) throws -> Self

    /// Extracts the symmetric key components.
    ///
    /// - Returns: The components of the symmetric key.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    func symmetricKeyComponents() throws -> SymmetricKeyComponents
}

// MARK: Key

/// A JWK holding a symmetric key.
public struct SymmetricKey: JWK {
    /// The JWK key type.
    public let keyType: JWKKeyType

    /// The JWK parameters.
    public let parameters: [String: String]

    /// The symmetric key required parameters
    public var requiredParameters: [String: String] {
        [
            JWKParameter.keyType.rawValue: self.keyType.rawValue,
            SymmetricKeyParameter.key.rawValue: self.key
        ]
    }

    /// The symmetric key represented as
    /// base64url encoding of the octet sequence containing the key data.
    public let key: String

    /// Initializes a JWK containing a symmetric key.
    ///
    /// - Parameters:
    ///   - key: The octet sequence containing the key data.
    ///   - parameters: Additional JWK parameters.
    public init(key: Data, additionalParameters parameters: [String: String] = [:]) {
        self.keyType = .OCT
        self.key = key.base64URLEncodedString()

        self.parameters = parameters.merging(
            [
                JWKParameter.keyType.rawValue: self.keyType.rawValue,
                SymmetricKeyParameter.key.rawValue: self.key
            ],
            uniquingKeysWith: { (_, new) in new }
        )
    }

    /// Creates a `SymmetricKey` JWK with the specified symmetric key and optional additional JWK parameters.
    ///
    /// - Parameters:
    ///   - key: The symmetirc key that the resulting JWK should represent.
    ///   - parameters: Any additional parameters to be contained in the JWK.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    public init(key: ExpressibleAsSymmetricKeyComponents, additionalParameters parameters: [String: String] = [:]) throws {
        guard let components = try? key.symmetricKeyComponents() else {
            throw JOSESwiftError.couldNotConstructJWK
        }

        self.init(
            key: components,
            additionalParameters: parameters
        )
    }

    /// Creates a `SymmetricKey` from the JSON representation of a symmetric key JWK.
    public init(data: Data) throws {
        self = try JSONDecoder().decode(SymmetricKey.self, from: data)
    }

    /// Converts the `SymmetricKey` JWK to the specified type.
    /// The specified type must conform to the `ExpressibleAsSymmetricKeyComponents` protocol.
    ///
    /// **Example:**
    /// `let keyData = try jwk.converted(to: Data.self)`
    ///
    /// - Parameter type: The type to convert the JWK to.
    /// - Returns: The type initialized with the key data.
    /// - Throws: A `JOSESwiftError` indicating any errors.
    public func converted<T>(to type: T.Type) throws -> T where T: ExpressibleAsSymmetricKeyComponents {
        guard let keyData = Data(base64URLEncoded: key) else {
            throw JOSESwiftError.symmetricKeyNotBase64URLEncoded
        }
        return try T.representing(symmetricKeyComponents: (keyData))
    }

    @available(iOS 11.0, *)
    public func withThumbprintAsKeyId(algorithm: JWKThumbprintAlgorithm = .SHA256) throws -> Self {
        let keyId = try thumbprint(algorithm: algorithm)
        return .init(key: try converted(to: Data.self), additionalParameters: parameters.merging([
            JWKParameter.keyIdentifier.rawValue: keyId
        ], uniquingKeysWith: { (_, new) in new }))
    }
}
