//
//  JOSEHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

/// A `JOSEHeader` is a JSON object representing various Header Parameters.
/// Moreover, a `JOSEHeader` is a `JOSEObjectComponent`. Therefore it can be initialized from and converted to `Data`.
protocol JOSEHeader: JOSEObjectComponent {
    var parameters: [String: Any] { get }
    init(parameters: [String: Any]) throws
    
    init?(_ data: Data)
    func data() -> Data
}

// `JOSEObjectComponent` implementation.
extension JOSEHeader {
    public init?(_ data: Data) {
        guard
            let json = try? JSONSerialization.jsonObject(with: data, options: []),
            let parameters = json as? [String: Any]
        else {
            return nil
        }
        
        try? self.init(parameters: parameters)
    }
    
    public func data() -> Data {
        // Forcing the try is ok here since we checked `isValidJSONObject(_:)` in `init(parameters:)` earlier.
        // The resulting data of this operation is UTF-8 encoded.
        return try! JSONSerialization.data(withJSONObject: parameters, options: [])
    }
}

extension JOSEHeader {
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
