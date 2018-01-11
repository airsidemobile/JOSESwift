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

/// A `JWKBuilder` builds a JWK from a given key.
internal protocol JWKBuilder {
    associatedtype KeyDataType

    /// Set the public key that the resulting JWK should contain.
    ///
    /// - Parameter publicKey: The public key to be contained in the resulting JWK.
    /// - Returns: A `JWKBuilder` containing the set public key that can be used
    ///            to set another key or parameter or to build a JWK.
    func set(publicKey: KeyDataType) -> Self

    /// Set the private key that the resulting JWK should contain.
    ///
    /// - Parameter privateKey: The private key to be contained in the resulting JWK.
    /// - Returns: A `JWKBuilder` containing the set private key that can be used
    ///            to set another key or parameter or to build a JWK.
    func set(privateKey: KeyDataType) -> Self

    /// Set or update the specified parameter to the specified value.
    ///
    /// - Parameters:
    ///   - parameter: The parameter to set or update.
    ///   - value: Teh value to set or update for the specified paramter.
    /// - Returns: A `JWKBuilder` containing the set parameter that can be used
    ///            to set another key or parameter or to build a JWK.
    func set(_ parameter: String, to value: Any) -> Self

    /// Set the desired key type.
    /// Setting the key type is required for `build()` to succeed.
    ///
    /// - Parameter keyType: The desired key type. Currently only `.RSA` keys are supported.
    /// - Returns: A `JWKBuilder` containing the set parameter that can be used
    ///            to set another key or parameter or to build a JWK.
    func set(keyType: JWKKeyType) -> Self

    /// Builds a JWK containing the previously set key(s).
    /// Make sure to set the JWK's key type using `set(keyType:)` before calling `build()`.
    ///
    /// - Returns: A JWK containing the previously set key(s).
    ///            `nil` if no key(s) set.
    func build() -> JWK?
}
