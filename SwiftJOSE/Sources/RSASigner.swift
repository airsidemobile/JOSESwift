//
//  RSASigner.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSASigner: Signer {
    let key: SecKey
    
    public init(key: SecKey) {
        self.key = key
    }
    
    public func sign(_ signingInput: Data, using algorithm: SigningAlgorithm) throws -> Data {
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
            throw SigningError.algorithmNotSupported
        }
        
        var signingError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, algorithm, signingInput as CFData, &signingError) else {
            throw SigningError.signingFailed(description: signingError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }
        
        return signature as Data
    }
}
