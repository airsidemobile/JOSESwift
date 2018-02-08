//
//  CryptoFactory.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 05.12.17.
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

/// Factory deciding which crypto implementation to use for which algorithm.
/// If there are different crypto implementations, e.g. for different platforms,
/// this factory decides which version to use.
struct CryptoFactory {

    /// Returns an asymmetric encrypter suitable for a given algorithm, initialized with a given public key.
    ///
    /// - Parameters:
    ///   - algorithm: The asymmetric algorithm to use.
    ///   - publicKey: The public key to initialize the asymmetric encrypter with.
    /// - Returns: The asymmetric encrypter suitable for the given algorithm, initialized with the given public key.
    static func encrypter(for algorithm: AsymmetricKeyAlgorithm, with publicKey: SecKey) -> AsymmetricEncrypter {
        switch algorithm {
        case .RSAPKCS:
            return RSAEncrypter(algorithm: algorithm, publicKey: publicKey)
        }
    }

    /// Returns a symmetric encrypter suitable for a given algorithm.
    ///
    /// - Parameter algorithm: The symmetric algorithm to use.
    /// - Returns: The symmetric encrypter suitable for the given algorithm.
    static func encrypter(for algorithm: SymmetricKeyAlgorithm) -> SymmetricEncrypter {
        switch algorithm {
        case .AES256CBCHS512:
            return AESEncrypter(algorithm: algorithm)
        }
    }

    /// Returns an asymmetric decrypter suitable for a given algorithm, initialized with a given private key.
    ///
    /// - Parameters:
    ///   - algorithm: The asymmetric algorithm to use.
    ///   - privateKey: The private key to initialize the asymmetric decrypter with.
    /// - Returns: The asymmetric decrypter suitable for the given algorithm, initialized with the given private key.
    // swiftlint:disable:next line_length
    static func decrypter(for algorithm: AsymmetricKeyAlgorithm, with privateKey: SecKey) -> AsymmetricDecrypter {
        switch algorithm {
        case .RSAPKCS:
            return RSADecrypter(algorithm: algorithm, privateKey: privateKey)
        }
    }

    /// Returns a symmetric decrypter suitable for a given algorithm.
    ///
    /// - Parameter algorithm: The symmetric algorithm to use.
    /// - Returns: The symmetric decrypter suitable for the given algorithm.
    static func decrypter(for algorithm: SymmetricKeyAlgorithm) -> SymmetricDecrypter {
        switch algorithm {
        case .AES256CBCHS512:
            return AESDecrypter(algorithm: algorithm)
        }
    }

    /// Returns a signer suitable for a given algorithm.
    ///
    /// - Parameters:
    ///   - algorithm: The signing algorithm to use.
    ///   - privateKey: The private key to initialize the signer with.
    /// - Returns: The signer suitable for a given algorithm, initialized with the given private key.
    static func signer(for algorithm: SignatureAlgorithm, with privateKey: SecKey) -> SignerProtocol {
        switch algorithm {
        case .RS512:
            return RSASigner(algorithm: algorithm, privateKey: privateKey)
        }
    }

    /// Returns a verifyer suitable for a given algorithm, initialized with a given public key.
    ///
    /// - Parameters:
    ///   - algorithm: The verifying algorithm to use.
    ///   - publicKey: The public key to initialize the verifyer with.
    /// - Returns: The verifyer suitable for a given algorithm, initialized with the given public key.
    static func verifyer(for algorithm: SignatureAlgorithm, with publicKey: SecKey) -> VerifierProtocol {
        switch algorithm {
        case .RS512:
            return RSAVerifier(algorithm: algorithm, publicKey: publicKey)
        }
    }

}
