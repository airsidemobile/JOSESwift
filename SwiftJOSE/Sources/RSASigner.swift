//
//  RSASigner.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSASigner: Signer {
    let algorithm: SigningAlgorithm
    let key: String
    
    public init(publicKey: String) {
        self.algorithm = .rs512
        self.key = publicKey
    }
    
    public func sign(_ signatureInput: Data) -> Data {
        let string = String.init(data: signatureInput, encoding: .utf8)!
        return "Signature(\(string))".data(using: .utf8)!
    }
}

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
