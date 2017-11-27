//
//  RSASigner.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/08/2017.
//

import Foundation

/// A `Signer` to sign an input with a `RSA` algorithm.
public struct RSASigner: Signer {
    let key: SecKey
    
    public init(key: SecKey) {
        self.key = key
    }
    
    public func sign(_ signingInput: Data, using algorithm: SigningAlgorithm) throws -> Data {
        // Check if SigningAlgorithm supports a secKeyAlgorithm and if the algorithm is supported to sign with a given private key.
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
            throw SigningError.algorithmNotSupported
        }
        
        // Sign the input with a given SecKeyAlgorithm and a private key, return signature if no error occured.
        var signingError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, algorithm, signingInput as CFData, &signingError) else {
            throw SigningError.signingFailed(description: signingError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }
        
        return signature as Data
    }
}
