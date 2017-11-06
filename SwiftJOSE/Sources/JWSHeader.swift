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
    
    init(parameters: [String: Any]) {
        // TODO: Assert that required JWS parameters are present.
        self.parameters = parameters
    }
    
    /// Initializes a `JWSHeader` with the specified algorithm.
    public init(algorithm: Algorithm) {
        self.init(parameters: ["alg": algorithm.rawValue])
    }
}

// Header parameters that both a JWS Header and a JWE Header must support.
extension JWSHeader: CommonHeaderParameterSpace {
    /// The algorithm used to sign the payload.
    public var algorithm: Algorithm {
        return Algorithm(rawValue: parameters["alg"] as! String)!
    }
    
    /// The JWK Set URL which refers to a resource for a set of JSON-encoded public keys,
    /// one of which corresponds to the key used to sign the JWS.
    public var jku: URL {
        return parameters["jku"] as! URL
    }
    
    /// The JSON Web key corresponding to the key used to digitally sign the JWS.
    public var jwk: String {
        return ""
    }
    
    /// The Key ID indicates the key which was used to secure the JWS.
    public var kid: String {
        return ""
    }
    
    /// The X.509 URL that referes to a resource for the X.509 public key certificate
    /// or certificate chain corresponding to the key used to sign the JWS.
    public var x5u: URL {
        return parameters["x5u"] as! URL
    }
    
    /// The X.509 certificate chain contains the X.509 public key certificate or
    /// certificate chain corresponding to the key used to sign the JWS.
    public var x5c: [String : Any] {
        return ["": ""]
    }
    
    /// The X.509 certificate SHA-1 thumbprint of the DER encoding of the X.509 certificate
    /// corresponding to the key used to sign the JWS.
    public var x5t: String {
        return ""
    }
    
    /// The X.509 certificate SHA-256 thumbprint of the DER encoding of the X.509 certificate
    /// corresponding to the key used to sign the JWS.
    public var x5tS256: String {
        return ""
    }
    
    /// The type to declare the media type of the JWS object.
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

extension JWSHeader: CompactDeserializable {
    public init(from deserializer: CompactDeserializer) {
        self = deserializer.deserialize(JWSHeader.self, at: ComponentCompactSerializedIndex.jwsHeaderIndex)
    }
}
