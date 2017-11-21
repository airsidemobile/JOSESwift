//
//  RSAVerifier.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 28/09/2017.
//

import Foundation

public struct RSAVerifier: Verifier {
    let key: SecKey
    
    public init(key: SecKey) {
        self.key = key
    }
    
    public func verify(_ signature: Data, against signingInput: Data, using algorithm: SigningAlgorithm) -> Bool {
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
            return false
        }
        
        var verifyError: Unmanaged<CFError>?
        guard SecKeyVerifySignature(key, algorithm, signingInput as CFData, signature as CFData, &verifyError) else {
            //TODO: throw verify error
            print("\(verifyError!)")
            return false
        }
        
        return true
    }
}
