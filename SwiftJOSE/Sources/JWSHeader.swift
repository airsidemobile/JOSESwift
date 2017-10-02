//
//  JWSHeader.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 27/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct JWSHeader: Header {
    let parameters: [String : Any]
    
    init(parameters: [String : Any]) {
        // assert required parameters for JWS
        self.parameters = parameters
    }
    
    public init(algorithm: SigningAlgorithm) {
        self.init(parameters: ["alg": algorithm.rawValue])
    }
    
    public var algorithm: SigningAlgorithm {
        let rawValue = parameters["alg"] as! String
        return SigningAlgorithm(rawValue: rawValue)!
    }
}
