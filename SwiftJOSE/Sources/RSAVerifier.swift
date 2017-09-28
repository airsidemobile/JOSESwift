//
//  RSAVerifier.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 28/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSAVerifier: Verifier {
    let algorithm: SigningAlgorithm
    let key: String
    
    public init(algorithm: SigningAlgorithm, key: String) {
        self.algorithm = algorithm
        self.key = key
    }
    
    public func verify(_ signature: Data, against signatureInput: Data) -> Bool {
        return true
    }
}
