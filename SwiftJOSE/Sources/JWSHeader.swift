//
//  JWSHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 27/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

/// The header of a `JWS` object.
public struct JWSHeader: JOSEHeader {
    let parameters: [String: Any]
    
    init(parameters: [String: Any]) throws {
        guard JSONSerialization.isValidJSONObject(parameters) else {
            throw DeserializationError.headerIsNotValidJSONObject
        }
        
        guard parameters["alg"] is String else {
            throw DeserializationError.requiredHeaderParameterMissing(parameter: "alg")
        }
        
        self.parameters = parameters
    }
    
    /// Initializes a `JWSHeader` with the specified algorithm.
    public init(algorithm: Algorithm) {
        // Forcing the try is ok here, since "alg" is the only required header parameter.
        try! self.init(parameters: ["alg": algorithm.rawValue])
    }
}

// Header parameters that both a JWS Header and a JWE Header must support.
extension JWSHeader {
    /// The algorithm used to sign the payload.
    public var algorithm: Algorithm {
        // Forced unwrap is ok here since we checked both that "alg" exists
        // and has a valid `Algorithm` value earlier
        return Algorithm(rawValue: parameters["alg"] as! String)!
    }
}
