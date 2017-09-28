//
//  JWSHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 27/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct JWSHeader: Header, CompactDeserializable {
    let parameters: [String : Any]
    
    public var algorithm: SigningAlgorithm {
        let rawValue = parameters["alg"] as! String
        return SigningAlgorithm(rawValue: rawValue)!
    }
    
    public init(algorithm: SigningAlgorithm) {
        self.init(parameters: ["alg": algorithm.rawValue])
    }
    
    internal init(parameters: [String : Any]) {
        // assert parameters["alg"]
        self.parameters = parameters
    }
    
    internal init(from deserializer: CompactDeserializer) {
        // assert parameters["alg"]
        self = deserializer.deserialize(JWSHeader.self, at: 0)
    }
}
