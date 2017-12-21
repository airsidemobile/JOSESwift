//
//  RSAVerifier.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 28/09/2017.
//

import Foundation

/// A `Verifier` to verify a signature created with a `RSA` algorithm. 
public struct RSAVerifier: VerifierProtocol {
    let algorithm: SigningAlgorithm
    let publicKey: SecKey

    public func verify(_ signingInput: Data, against signature: Data) throws -> Bool {
        // Check if SigningAlgorithm supports a secKeyAlgorithm and if the algorithm is supported to verify with a given public key.
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            throw SigningError.algorithmNotSupported
        }

        // Verify the signature against an input with a given SecKeyAlgorithm and a public key, return true if no error occured and the signature is verified.
        var verificationError: Unmanaged<CFError>?
        guard SecKeyVerifySignature(publicKey, algorithm, signingInput as CFData, signature as CFData, &verificationError) else {
            if let description = verificationError?.takeRetainedValue().localizedDescription {
                throw SigningError.verificationFailed(descritpion: description)
            }

            return false
        }

        return true
    }
}
