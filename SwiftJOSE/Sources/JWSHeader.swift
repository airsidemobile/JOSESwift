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
        // TODO: Assert that required JWS parameters are present.
        guard let algorithm = parameters["alg"] as? String, Algorithm(rawValue: algorithm) != nil else {
            throw NSError(domain: "com.airsidemobile.SwiftJOSE.error", code: 666, userInfo: nil) //TODO: Implement error class as soon as the error handling stands
        }
        
        self.parameters = parameters
    }
    
    /// Initializes a `JWSHeader` with the specified algorithm.
    public init(algorithm: Algorithm) {
        try! self.init(parameters: ["alg": algorithm.rawValue])
    }
}

// Header parameters that both a JWS Header and a JWE Header must support.
extension JWSHeader: CommonHeaderParameterSpace {
    /// The algorithm used to sign the payload.
    public var algorithm: Algorithm {
        return Algorithm(rawValue: parameters["alg"] as! String)!
    }
}

extension JWSHeader: CompactDeserializable {
    public init(from deserializer: CompactDeserializer) {
        self = deserializer.deserialize(JWSHeader.self, at: ComponentCompactSerializedIndex.jwsHeaderIndex)
    }
}
