//
//  JWKBuilder.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
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

    /// Builds a JWK containing the previously set key(s).
    ///
    /// - Returns: A JWK containing the previously set key(s).
    ///            `nil` if no key(s) set.
    func build() -> JWK?
}
