//
//  RSASigner.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/08/2017.
//  Copyright © 2018 Airside Mobile Inc. All rights reserved.
//

import Foundation

/// A `Signer` to sign an input with a `RSA` algorithm.
public struct RSASigner: SignerProtocol {
    let algorithm: SigningAlgorithm
    let privateKey: SecKey

    public func sign(_ signingInput: Data) throws -> Data {
        // Check if SigningAlgorithm supports a secKeyAlgorithm and if the algorithm is supported to sign with a given private key.
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw SigningError.algorithmNotSupported
        }

        // Sign the input with a given SecKeyAlgorithm and a private key, return signature if no error occured.
        var signingError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, signingInput as CFData, &signingError) else {
            throw SigningError.signingFailed(description: signingError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }

        return signature as Data
    }
}
