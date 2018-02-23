//
//  Verifier.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 28/09/2017.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import Foundation

protocol VerifierProtocol {
    var algorithm: SignatureAlgorithm { get }

    /// Verifies a signature against a given signing input with a specific algorithm and the corresponding key.
    ///
    /// - Parameters:
    ///   - signingInput: The input to verify against.
    ///   - signature: The signature to verify.
    /// - Returns: True if the signature is verified, false if it is not verified.
    /// - Throws: `JWSError` if any error occurs during verifying.
    func verify(_ signingInput: Data, against signature: Data) throws -> Bool
}

public struct Verifier<KeyType> {
    let verifier: VerifierProtocol

    public init?(verifyingAlgorithm: SignatureAlgorithm, publicKey: KeyType) {
        switch verifyingAlgorithm {
        case .RS512:
            if type(of: publicKey) is RSAVerifier.KeyType.Type {
                let key = publicKey as! RSAVerifier.KeyType
                self.verifier = RSAVerifier(algorithm: verifyingAlgorithm, publicKey: key)
            } else {
                return nil
            }
        }
    }

    internal func verify(header: JWSHeader, and payload: Payload, against signature: Data) throws -> Bool {
        guard let alg = header.algorithm, alg == verifier.algorithm else {
            throw JWSError.algorithmMismatch
        }

        guard let signingInput = [header, payload].asJOSESigningInput() else {
            throw JWSError.cannotComputeSigningInput
        }

        return try verifier.verify(signingInput, against: signature)
    }
}
