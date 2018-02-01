//
//  JWKBuilder.swift
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

/// A key type that can be converted to a JWK.
public protocol JWKConvertible { }

public protocol RSAPublicKeyConvertible: JWKConvertible {
    var modulus: Data? { get }
    var publicExponent: Data? { get }
}

public protocol RSAPrivateKeyConvertible: RSAPublicKeyConvertible {
    var privateExponent: Data? { get }
}

/// A generic `JWKBuilder` that builds a JWK from a given `JWKConvertible` key.
public class JWKBuilder<T> where T: JWKConvertible {

    private var publicKey: T?
    private var privateKey: T?
    private var parameters: [String: Any] = [:]
    private var keyType: JWKKeyType?

    /// Initializes a generic `JWKBuilder`.
    public init() { }

    /// Set the public key that the resulting JWK should contain.
    ///
    /// - Parameter publicKey: The public key to be contained in the resulting JWK.
    /// - Returns: A `JWKBuilder` containing the set public key that can be used
    ///            to set another key or parameter or to build a JWK.
    func set(publicKey: T) -> Self {
        self.publicKey = publicKey

        return self
    }

    /// Set the private key that the resulting JWK should contain.
    ///
    /// - Parameter privateKey: The private key to be contained in the resulting JWK.
    /// - Returns: A `JWKBuilder` containing the set private key that can be used
    ///            to set another key or parameter or to build a JWK.
    func set(privateKey: T) -> Self {
        self.privateKey = privateKey

        return self
    }

    /// Set or update the specified parameter to the specified value.
    ///
    /// - Parameters:
    ///   - parameter: The parameter to set or update.
    ///   - value: Teh value to set or update for the specified paramter.
    /// - Returns: A `JWKBuilder` containing the set parameter that can be used
    ///            to set another key or parameter or to build a JWK.
    func set(_ parameter: String, to value: Any) -> Self {
        parameters[parameter] = value

        return self
    }

    /// Set the desired key type.
    /// Setting the key type is required for `build()` to succeed.
    ///
    /// - Parameter keyType: The desired key type. Currently only `.RSA` keys are supported.
    /// - Returns: A `JWKBuilder` containing the set parameter that can be used
    ///            to set another key or parameter or to build a JWK.
    func set(keyType: JWKKeyType) -> Self {
        self.keyType = keyType

        return self
    }

    /// Builds a JWK containing the previously set key(s).
    /// Make sure to set the JWK's key type using `set(keyType:)` before calling `build()`.
    ///
    /// - Returns: A JWK containing the previously set key(s).
    ///            `nil` if no key(s) set.
    func build() -> JWK? {
        // The key type is a required parameter.
        guard let keyType = self.keyType else {
            return nil
        }

        switch keyType {
        case .RSA:
            return buildRSA()
        }
    }

    private func buildRSA() -> JWK? {
        if let publicKey = self.publicKey as? RSAPublicKeyConvertible, self.privateKey == nil {
            return try? RSAPublicKey(publicKey: publicKey, additionalParameters: parameters)
        } else if let privateKey = self.privateKey as? RSAPrivateKeyConvertible {
            return try? RSAPrivateKey(privateKey: privateKey, additionalParameters: parameters)
        }

        return nil
    }
}
