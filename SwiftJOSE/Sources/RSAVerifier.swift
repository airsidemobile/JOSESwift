//
//  RSAVerifier.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 28/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSAVerifier: Verifier {
    let key: SecKey
    
    public init(key: SecKey) {
        self.key = key
    }
    
    public func verify(_ signature: Data, against signingInput: Data, using algorithm: Algorithm) -> Bool {
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
            return false
        }
        
            return false
        }
        
        return true
    }
}
