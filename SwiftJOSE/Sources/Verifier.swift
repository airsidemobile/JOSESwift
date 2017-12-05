//
//  Verifier.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 28/09/2017.
//

import Foundation

public protocol Verifier {
    /// Initializes a `Verifier` with a specified key.
    init(key: SecKey)

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
    func verify(_ signature: Data, against signingInput: Data, using algorithm: SigningAlgorithm) throws -> Bool
}
