//
//  JWEHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 12/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

/// The header of a `JWE` object.
public struct JWEHeader: JOSEHeader {
    let parameters: [String: Any]
    
    init(parameters: [String: Any]) throws {
        guard JSONSerialization.isValidJSONObject(parameters) else {
            throw DeserializationError.headerIsNotValidJSONObject
        }
        
        guard let alg = parameters["alg"] as? String else {
            throw DeserializationError.requiredHeaderParameterMissing(parameter: "alg")
        }
        guard Algorithm(rawValue: alg) != nil else {
            throw DeserializationError.headerParameterValueIsInvalid(parameter: "alg", value: alg)
        }
        
        guard let enc = parameters["enc"] as? String else {
            throw DeserializationError.requiredHeaderParameterMissing(parameter: "enc")
        }
        guard Algorithm(rawValue: enc) != nil else {
            throw DeserializationError.headerParameterValueIsInvalid(parameter: "enc", value: enc)
        }
        
        self.parameters = parameters
    }
    
    /// Initializes a `JWEHeader` with the specified algorithm and signing algorithm.
    public init(algorithm: Algorithm, encryptionAlgorithm: Algorithm) {
        // Forcing the try is ok here, since "alg" and "enc" are the only required header parameters.
        try! self.init(parameters: [
            "alg": algorithm.rawValue,
            "enc": encryptionAlgorithm.rawValue
        ])
    }
}

// Header parameters that both a JWS Header and a JWE Header must support.
extension JWEHeader {
    /// The algorithm used to encrypt or determine the value of the Content Encryption Key.
    public var algorithm: Algorithm {
        // Forced unwrap is ok here since we checked both that "alg" exists
        // and has a valid `Algorithm` value earlier
        return Algorithm(rawValue: parameters["alg"] as! String)!
    }
}

// Header parameters that are specific to a JWE Header.
public extension JWEHeader {
    /// The encryption algorithm used to perform authenicated encryption of the plaintext
    /// to produce the ciphertext and the Authentication Tag.
    public var encryptionAlgorithm: Algorithm {
        // Forced unwrap is ok here since we checked both that "enc" exists
        // and has a valid `Algorithm` value earlier
        return Algorithm(rawValue: parameters["enc"] as! String)!
    }
}
