//
//  EC.swift
//  JOSESwift
//
//  Created by Jarrod Moldrich on 02.07.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Jarrod Moldrich
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
import Security

internal enum ECError: Error {
    case algorithmNotSupported
    case signingFailed(description: String)
    case verifyingFailed(description: String)
    case encryptingFailed(description: String)
    case decryptingFailed(description: String)
}

/// Identifies the curve type parameter of a JWK representing an elliptic curve key
/// See [RFC-7518](https://tools.ietf.org/html/rfc7518#section-7.4) for details.
public enum ECCurveType: String, Codable {
    case P256 = "P-256"
    case P384 = "P-384"
    case P521 = "P-521"

    var keySize: Int {
        switch self {
        case .P256:
            return 256
        case .P384:
            return 384
        case .P521:
            return 521
        }
    }

    static func fromKeySize(_ size: Int) -> ECCurveType? {
        switch size {
        case 256:
            return .P256
        case 384:
            return .P384
        case 521:
            return .P521
        default:
            return nil
        }
    }

    static func fromOctetSize(_ size: Int) -> ECCurveType? {
        switch size {
        case 32:
            return .P256
        case 48:
            return .P384
        case 66:
            return .P521
        default:
            return nil
        }
    }
}

fileprivate extension SignatureAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .ES256:
            return .ecdsaSignatureMessageX962SHA256
        case .ES384:
            return .ecdsaSignatureMessageX962SHA384
        case .ES512:
            return .ecdsaSignatureMessageX962SHA512
        default:
            return nil
        }
    }
}

internal struct EC {
    typealias KeyType = SecKey

    ///  Signs input data with a given elliptic curve algorithm and the corresponding private key.
    ///
    /// - Parameters:
    ///   - signingInput: The data to sign.
    ///   - privateKey: The private key used by the `SignatureAlgorithm`.
    ///   - algorithm: The algorithm to sign the input data.
    /// - Returns: The signature.
    /// - Throws: `ECError` if any errors occur while signing the input data.
    static func sign(_ signingInput: Data, with privateKey: KeyType, and algorithm: SignatureAlgorithm) throws -> Data {
        // Check if `SignatureAlgorithm` supports a `SecKeyAlgorithm` and
        // if the algorithm is supported to sign with a given private key.
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw ECError.algorithmNotSupported
        }

        // Sign the input with a given `SecKeyAlgorithm` and a private key.
        var signingError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, signingInput as CFData, &signingError) else {
            throw ECError.signingFailed(
                description: signingError?.takeRetainedValue().localizedDescription ?? "No description available."
            )
        }

        return signature as Data
    }

    /// Verifies input data against a signature with a given elliptic curve algorithm and the corresponding public key.
    ///
    /// - Parameters:
    ///   - verifyingInput: The data to verify.
    ///   - signature: The signature to verify against.
    ///   - publicKey: The public key used by the `SignatureAlgorithm`.
    ///   - algorithm: The algorithm to verify the input data.
    /// - Returns: True if the signature is verified, false if it is not verified.
    /// - Throws: `ECError` if any errors occur while verifying the input data against the signature.
    static func verify(_ verifyingInput: Data, against signature: Data, with publicKey: KeyType, and algorithm: SignatureAlgorithm) throws -> Bool {
        // Check if `SignatureAlgorithm` supports a `SecKeyAlgorithm` and
        // if the algorithm is supported to verify with a given public key.
        guard
            let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm)
        else {
            throw ECError.algorithmNotSupported
        }

        // Verify the signature against an input with a given `SecKeyAlgorithm` and a public key.
        var verificationError: Unmanaged<CFError>?
        guard
            SecKeyVerifySignature(
                publicKey, algorithm, verifyingInput as CFData, signature as CFData, &verificationError
            )
        else {
            if let description = verificationError?.takeRetainedValue().localizedDescription {
                throw ECError.verifyingFailed(description: description)
            }

            return false
        }

        return true
    }

}
