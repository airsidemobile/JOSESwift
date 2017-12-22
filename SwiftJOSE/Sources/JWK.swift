//
//  JWK.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation

/// JWK related errors
///
/// - JWKToJSONConversionFailed: Thrown if the JWK parameters could not be converted to valid JSON format.
public enum JWKError: Error {
    case JWKToJSONConversionFailed
}

/// A JWK object that represents a key or a key pair of a certain type.
/// Check `KeyType` for the supported key types.
public protocol JWK {
    /// The the cryptographic algorithm family used with the JWK.
    var keyType: JWKKeyType { get }
    
    /// The parameters of the JWK representing the properties of the key(s), including the value(s).
    /// Check [RFC 7517, Section 4](https://tools.ietf.org/html/rfc7517#section-4) and
    /// [RFC 7518, Section 6](https://tools.ietf.org/html/rfc7518#section-6) for possible parameters.
    var parameters: [String: Any] { get }
    
    /// Accesses the specified parameter.
    /// The parameters of the JWK representing the properties of the key(s), including the value(s).
    /// Check [RFC 7517, Section 4](https://tools.ietf.org/html/rfc7517#section-4) and
    /// [RFC 7518, Section 6](https://tools.ietf.org/html/rfc7518#section-6) for possible parameters.
    ///
    /// - Parameter parameter: The desired parameter.
    subscript(parameter: String) -> Any? { get }
    
    /// Computes the JSON representation of the JWK.
    ///
    /// - Returns: The JSON representation of the JWK as `String`.
    /// - Throws: `JWKError.JWKToJSONConversionFailed` if an error occurs.
    func jsonString() throws -> String
    
    /// Computes the JSON representation of the JWK.
    ///
    /// - Returns: The JSON representation of the JWK as `Data`.
    /// - Throws: `JWKError.JWKToJSONConversionFailed` if an error occurs.
    func jsonData() throws -> Data
}

/// A JWK representing a public key.
public protocol PublicKey: JWK { }

/// A JWK representing a private key.
public protocol PrivateKey: JWK { }

/// A JWK representing a key pair.
public protocol KeyPair: JWK { }
