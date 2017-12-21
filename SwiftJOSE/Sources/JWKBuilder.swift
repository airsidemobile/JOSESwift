//
//  JWKBuilder.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation

internal enum JWKType {
    case publicKey
    case privateKey
    case keyPair
}


/// A `JWKBuilder` builds a JWK from a given key.
internal protocol JWKBuilder {
    associatedtype KeyDataType
    
    
    /// Set the public key that the resulting JWK should contain.
    ///
    /// - Parameter publicKey: The public key to be contained in the resulting JWK.
    /// - Returns: A `JWKBuilder` containing the set public key that can be used
    ///            to set another key or to build a JWK.
    func set(publicKey: KeyDataType) -> Self
    
    /// Set the private key that the resulting JWK should contain.
    ///
    /// - Parameter privateKey: The private key to be contained in the resulting JWK.
    /// - Returns: A `JWKBuilder` containing the set private key that can be used
    ///            to set another key or to build a JWK.
    func set(privateKey: KeyDataType) -> Self
    
    
    /// Checks the type of the set key(s) and returns the `JWKType` that the JWK
    /// returned by a call to `build()` will return.
    ///
    /// - Returns: The type of the JWK that a call to `build()` will return.
    func type() -> JWKType?
    
    func build() -> JWK?
}
