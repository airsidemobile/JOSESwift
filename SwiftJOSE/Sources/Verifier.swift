//
//  Verifier.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 28/09/2017.
//

import Foundation

protocol VerifierProtocol {
    var algorithm: SigningAlgorithm { get }

    /// Initializes a `Verifier` with a specified key and signing algorithm.
    init(algorithm: SigningAlgorithm, publicKey: SecKey)

    /**
     Verifies a signature against a given signing input with a specific algorithm and the corresponding key.
     - Parameters:
        - signature: The signature to verify.
        - signingInput: The input to verify against.
        - algorithm: The algorithm with which the signature was created.
     
     - Throws:
     - `SigningError.verificationFailed(description: String)`: If verifying failed with a specific error description.
     
     - Returns: True if the signature is verified, false if it is not verified.
     */
    func verify(_ signingInput: Data, against signature: Data) throws -> Bool
}

public struct Verifier {
    let verifier: VerifierProtocol

    public init(signingAlgorithm: SigningAlgorithm, publicKey: SecKey) {
        self.verifier = CryptoFactory.verifyer(for: signingAlgorithm, with: publicKey)
    }

    func verify(header: JWSHeader, and payload: Payload, against signature: Data) throws -> Bool {
        guard let alg = header.algorithm, alg == verifier.algorithm else {
            throw SigningError.algorithmMismatch
        }

        guard let signingInput = [header, payload].asJOSESigningInput() else {
            throw SigningError.cannotComputeSigningInput
        }

        return try verifier.verify(signingInput, against: signature)
    }
}
