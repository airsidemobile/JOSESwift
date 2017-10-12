//
//  JWSHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 27/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct JWSHeader: JOSEHeader {
    public let parameters: [String: Any]
    
    public init(parameters: [String: Any]) {
        // TODO: Assert that required JWS parameters are present.
        self.parameters = parameters
    }
    
    /// Initializes a `JWSHeader` with the specified algorithm.
    public init(algorithm: SigningAlgorithm) {
        self.init(parameters: ["alg": algorithm.rawValue])
    }
}

extension JWSHeader: CompactDeserializable {
    public init(from deserializer: CompactDeserializer) {
        self = deserializer.deserialize(JWSHeader.self, at: 0)
    }
}
