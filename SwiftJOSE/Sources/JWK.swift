//
//  JWK.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation

public enum JWKError: Error {
    case JWKToJSONConversionFailed
}

/// The key type parameter of a JWK identifies the cryptographic algorithm
/// family used with the key(s) represented by the JWK.
///
/// - RSA
public enum KeyType: String {
    case RSA = "RSA"
}

/// A JWK object that represents a key or a key pair of a certain type.
/// Check `KeyType` for the supproted key types.
public protocol JWK {
    ///  The the cryptographic algorithm family used with the JWK.
    var keyType: KeyType { get }
    
    /// The parameters of the JWK representing the properties of the key, including its value.
    /// Check [RFC 7517, Section 4](https://tools.ietf.org/html/rfc7517#section-4) and
    /// [RFC 7518, Section 6](https://tools.ietf.org/html/rfc7518#section-6) for possible parameters.
    var parameters: [String: Any] { get }
    
    
    /// Computes the JSON representation of the JWK.
    ///
    /// - Returns: The JSON representation of the JWK as `String`.
    /// - Throws: `JWKError.JWKToJSONConversionFailed` if an error occurs.
    func json() throws -> String
    
    /// Computes the JSON representation of the JWK.
    ///
    /// - Returns: The JSON representation of the JWK as `Data`.
    /// - Throws: `JWKError.JWKToJSONConversionFailed` if an error occurs.
    func json() throws -> Data
}

public extension JWK {
    func json() throws -> String {
        guard JSONSerialization.isValidJSONObject(parameters) else {
            throw JWKError.JWKToJSONConversionFailed
        }
        
        // The forced unwrap is ok here since we checked `isValidJSONObject` above.
        // swiftlint:disable:next_line force_try
        let jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])
        
        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            throw JWKError.JWKToJSONConversionFailed
        }
        
        return jsonString
    }
    
    func json() throws -> Data {
        guard JSONSerialization.isValidJSONObject(parameters) else {
            throw JWKError.JWKToJSONConversionFailed
        }
        
        // The forced unwrap is ok here since we checked `isValidJSONObject` above.
        // swiftlint:disable:next_line force_try
        let jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])
        
        return jsonData
    }
}
