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
    public init(algorithm: SigningAlgorithm) {
        // Forcing the try is ok here, since "alg" is the only required header parameter.
        try! self.init(parameters: ["alg": algorithm.rawValue])
    }
}

extension JWSHeader {
    /// The algorithm used to sign the payload.
    public var algorithm: SigningAlgorithm? {
        // Forced unwrap is ok here since we checked both that "alg" exists
        // and holds a `String` value in `init(parameters:)`
        return SigningAlgorithm(rawValue: parameters["alg"] as! String)
    }
}

extension JWSHeader: CommonHeaderParameterSpace {
    /// The JWK Set URL which refers to a resource for a set of JSON-encoded public keys,
    /// one of which corresponds to the key used to sign the JWS.
    public var jku: URL? {
        return parameters["jku"] as? URL
    }
    
    /// The JSON Web key corresponding to the key used to digitally sign the JWS.
    public var jwk: String? {
        return parameters["jwk"] as? String
    }
    
    /// The Key ID indicates the key which was used to secure the JWS.
    public var kid: String? {
        return parameters["kid"] as? String
    }
    
    /// The X.509 URL that referes to a resource for the X.509 public key certificate
    /// or certificate chain corresponding to the key used to sign the JWS.
    public var x5u: URL? {
        return parameters["x5u"] as? URL
    }
    
    /// The X.509 certificate chain contains the X.509 public key certificate or
    /// certificate chain corresponding to the key used to sign the JWS.
    public var x5c: [String : Any]? {
        return parameters["x5c"] as? [String: Any]
    }
    
    /// The X.509 certificate SHA-1 thumbprint of the DER encoding of the X.509 certificate
    /// corresponding to the key used to sign the JWS.
    public var x5t: String? {
        return parameters["x5t"] as? String
    }
    
    /// The X.509 certificate SHA-256 thumbprint of the DER encoding of the X.509 certificate
    /// corresponding to the key used to sign the JWS.
    public var x5tS256: String? {
        return parameters["jwk"] as? String
    }
    
    /// The type to declare the media type of the JWS object.
    public var typ: String? {
        return parameters["typ"] as? String
    }
    
    /// The content type to declare the media type of the secured content (payload).
    public var cty: String? {
        return parameters["cty"] as? String
    }
    
    /// The critical header parameter indicates the header parameter extensions.
    public var crit: [String]? {
        return parameters["crit"] as? [String]
    }
}
