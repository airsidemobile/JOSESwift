//
//  JWSHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 27/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

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

// Header parameters that both a `JWSHeader` and a `JWEHeader` must support.
extension JWSHeader: CommonHeaderParameterSpace {
    /// The algorithm used to sign the payload.
    public var algorithm: Algorithm {
        return Algorithm(rawValue: parameters["alg"] as! String)!
    }
}

extension JWSHeader: CompactDeserializable {
    public init(from deserializer: CompactDeserializer) {
        self = deserializer.deserialize(JWSHeader.self, at: 0)
    }
}
