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
    
    public func verify(_ signature: Data, against signingInput: Data, using algorithm: SigningAlgorithm) throws -> Bool {
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(key, .verify, algorithm) else {
            throw SigningError.algorithmNotSupported
        }
        
        var verificationError: Unmanaged<CFError>?
        guard SecKeyVerifySignature(key, algorithm, signingInput as CFData, signature as CFData, &verificationError) else {
            if let description = verificationError?.takeRetainedValue().localizedDescription {
                throw SigningError.verificationFailed(descritpion: description)
            }
            
            return false
        }
        
        return true
    }
}
