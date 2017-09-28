//
//  RSAVerifier.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 28/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSAVerifier: Verifier {
    let key: String
    
    var supportedAlgorithms: [SigningAlgorithm] {
        return [ .rs512 ]
    }
    
    public init(key: String) {
        self.key = key
    }
    
    public func verify(_ signature: Signature, against signingInput: Data, using algorithm: SigningAlgorithm) -> Bool {
        guard supportedAlgorithms.contains(algorithm) else {
            return false
        }
        
        return true
    }
}
