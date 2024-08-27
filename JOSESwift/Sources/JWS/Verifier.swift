//
//  Verifier.swift
//  JOSESwift
//
//  Created by Daniel Egger on 28/09/2017.
//  Modified by Jarrod Moldrich on 02.07.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
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

public struct Verifier {
    let verifier: VerifierProtocol

    /// Constructs a verifyer used to verify a JWS.
    ///
    /// - Parameters:
    ///   - verifyingAlgorithm: The desired `SignatureAlgorithm`.
    ///   - key: The key used to verify the JWS's signature or message authentication code (MAC).
    ///     Currently supported key types are: `SecKey` and `Data`.
    ///     - For _digital signature algorithms_ it is the sender's public key (`SecKey`)
    ///       with which the JWS signature should be verified.
    ///     - For _MAC algorithms_ it is the secret symmetric key (`Data`)
    ///       shared between the sender and the recipient.
    /// - Returns: A fully initialized `Verifier` or `nil` if provided key is of the wrong type.
    public init?<KeyType>(verifyingAlgorithm: SignatureAlgorithm, key: KeyType) {
        switch verifyingAlgorithm {
        case .HS256, .HS384, .HS512:
            guard type(of: key) is HMACVerifier.KeyType.Type else {
                return nil
            }
            // swiftlint:disable:next force_cast
            self.verifier = HMACVerifier(algorithm: verifyingAlgorithm, key: key as! HMACVerifier.KeyType)
        case .RS256, .RS384, .RS512, .PS256, .PS384, .PS512:
            guard type(of: key) is RSAVerifier.KeyType.Type else {
                return nil
            }
            // swiftlint:disable:next force_cast
            self.verifier = RSAVerifier(algorithm: verifyingAlgorithm, publicKey: key as! RSAVerifier.KeyType)
        case .ES256, .ES384, .ES512:
            guard type(of: key) is ECVerifier.KeyType.Type else {
                return nil
            }
            self.verifier = ECVerifier(algorithm: verifyingAlgorithm, publicKey: key as! ECVerifier.KeyType)
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

// MARK: - Deprecated API

extension Verifier {
    @available(*, deprecated, message: "Use `init?(verifyingAlgorithm: SignatureAlgorithm, key: KeyType)` instead")
    public init?<KeyType>(verifyingAlgorithm: SignatureAlgorithm, publicKey: KeyType) {
        self.init(verifyingAlgorithm: verifyingAlgorithm, key: publicKey)
    }
}
