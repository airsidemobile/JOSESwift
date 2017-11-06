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
    
    init(parameters: [String: Any]) {
        // TODO: Assert that required JWE parameters are present.
        self.parameters = parameters
    }
    
    /// Initializes a `JWEHeader` with the specified algorithm and signing algorithm.
    public init(algorithm: Algorithm, encryptionAlgorithm: Algorithm) {
        self.init(parameters: [
            "alg": algorithm.rawValue,
            "enc": encryptionAlgorithm.rawValue
        ])
    }
}

// Header parameters that both a JWS Header and a JWE Header must support.
extension JWEHeader: CommonHeaderParameterSpace {
    /// The algorithm used to encrypt or determine the value of the Content Encryption Key.
    public var algorithm: Algorithm {
        return Algorithm(rawValue: parameters["alg"] as! String)!
    }
    
    /// The JWK Set URL which refers to a resource for a set of JSON-encoded public keys,
    /// one of which corresponds to the key used to encrypt the JWE.
    public var jku: URL {
        return parameters["jku"] as! URL
    }
    
    /// The JSON Web key corresponding to the key used to encrypt the JWE.
    public var jwk: String {
        return ""
    }
    
    /// The Key ID indicates the key which was used to encrypt the JWE.
    public var kid: String {
        return ""
    }
    
    /// The X.509 URL that referes to a resource for the X.509 public key certificate
    /// or certificate chain corresponding to the key used to encrypt the JWE.
    public var x5u: URL {
        return parameters["x5u"] as! URL
    }
    
    /// The X.509 certificate chain contains the X.509 public key certificate or
    /// certificate chain corresponding to the key used to encrypt the JWE.
    public var x5c: [String : Any] {
        return ["": ""]
    }
    
    /// The X.509 certificate SHA-1 thumbprint of the DER encoding of the X.509 certificate
    /// corresponding to the key used to encrypt the JWE.
    public var x5t: String {
        return ""
    }
    
    /// The X.509 certificate SHA-256 thumbprint of the DER encoding of the X.509 certificate
    /// corresponding to the key used to encrypt the JWE.
    public var x5tS256: String {
        return ""
    }
    
    /// The type to declare the media type of the JWE object.
    public var typ: JOSEObjectComponent.Type {
        return JWSHeader.self
    }
    
    /// The content type to declare the media type of the secured content (payload).
    public var cty: String {
        return ""
    }
    
    /// The critical header parameter indicates the header parameter extensions.
    public var crit: [String] {
        return [""]
    }
}

// Header parameters that are specific to a JWE Header.
public extension JWEHeader {
    /// The encryption algorithm used to perform authenicated encryption of the plaintext
    /// to produce the ciphertext and the Authentication Tag.
    public var encryptionAlgorithm: Algorithm {
        return Algorithm(rawValue: parameters["enc"] as! String)!
    }
}

extension JWEHeader: CompactDeserializable {
    public init(from deserializer: CompactDeserializer) {
        self = deserializer.deserialize(JWEHeader.self, at: 0)
    }
}
