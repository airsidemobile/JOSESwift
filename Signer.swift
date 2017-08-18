//
//  Signer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public enum SigningAlgorithm {
    case rs512
}

public struct Signer {
    let algorithm: SigningAlgorithm
    let key: String
    
    public init(algorithm: SigningAlgorithm, key: String) {
        self.algorithm = algorithm
        self.key = key
    }
    
    func sign(_ jws: JWS) -> String {
        return ">>>Signature<<<"
    }
}
