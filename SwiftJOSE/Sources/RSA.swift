//
//  RSA.swift
//  SwiftJOSE
//
//  Created by Carol Capek on 06.02.18.
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

fileprivate extension SignatureAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .RS512:
            return .rsaSignatureMessagePKCS1v15SHA512
        }
    }
}

fileprivate extension AsymmetricKeyAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .RSAPKCS:
            return .rsaEncryptionPKCS1
        }
    }

    /// Checks if the plain text length does not exceed the maximum
    /// for the chosen algorithm and the corresponding public key.
    func isPlainTextLengthSatisfied(_ plainText: Data, for publicKey: SecKey) -> Bool {
        switch self {
        case .RSAPKCS:
            // For detailed information about the allowed plain text length for RSAES-PKCS1-v1_5,
            // please refer to the RFC(https://tools.ietf.org/html/rfc3447#section-7.2).
            return plainText.count < (SecKeyGetBlockSize(publicKey) - 11)
        }
    }

    func isCipherTextLenghtSatisfied(_ cipherText: Data, for privateKey: SecKey) -> Bool {
        switch self {
        case .RSAPKCS:
            return cipherText.count == SecKeyGetBlockSize(privateKey)
        }
    }
}

internal struct RSA {

    ///  DESCRITPION
    ///
    /// - Parameters:
    ///   - signingInput:
    ///   - privateKey:
    ///   - algorithm:
    /// - Returns:
    /// - Throws:
    static func sign(_ signingInput: Data, with privateKey: SecKey, and algorithm: SignatureAlgorithm) throws -> Data {
        // Check if `SignatureAlgorithm` supports a `SecKeyAlgorithm` and if the algorithm is supported to sign with a given private key.
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw SigningError.algorithmNotSupported
        }

        // Sign the input with a given `SecKeyAlgorithm` and a private key.
        var signingError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, signingInput as CFData, &signingError) else {
            throw SigningError.signingFailed(description: signingError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }

        return signature as Data
    }

    static func verify(_ verifyingInput: Data, against signature: Data, with publicKey: SecKey, and algorithm: SignatureAlgorithm) throws -> Bool {
        // Check if `SignatureAlgorithm` supports a `SecKeyAlgorithm` and if the algorithm is supported to verify with a given public key.
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            throw SigningError.algorithmNotSupported
        }

        // Verify the signature against an input with a given `SecKeyAlgorithm` and a public key.
        var verificationError: Unmanaged<CFError>?
        guard SecKeyVerifySignature(publicKey, algorithm, verifyingInput as CFData, signature as CFData, &verificationError) else {
            if let description = verificationError?.takeRetainedValue().localizedDescription {
                throw SigningError.verificationFailed(descritpion: description)
            }

            return false
        }

        return true
    }

    static func encrypt(_ plaintext: Data, with publicKey: SecKey, and algorithm: AsymmetricKeyAlgorithm) throws -> Data {
        // Check if `AsymmetricKeyAlgorithm` supports a `SecKeyAlgorithm` and if the algorithm is supported to encrypt with a given public key.
        guard let secKeyAlgorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(publicKey, .encrypt, secKeyAlgorithm) else {
            throw EncryptionError.encryptionAlgorithmNotSupported
        }

        // Check if the plain text length does not exceed the maximum.
        // e.g. for RSAPKCS the plaintext must be 11 bytes smaller than the public key's modulus.
        guard algorithm.isPlainTextLengthSatisfied(plaintext, for: publicKey) else {
            throw EncryptionError.plainTextLengthNotSatisfied
        }

        // Encrypt the plain text with a given `SecKeyAlgorithm` and a public key.
        var encryptionError: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(publicKey, secKeyAlgorithm, plaintext as CFData, &encryptionError) else {
            throw EncryptionError.encryptingFailed(description: encryptionError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }

        return cipherText as Data
    }

    static func decrypt(_ ciphertext: Data, with privateKey: SecKey, and algorithm: AsymmetricKeyAlgorithm) throws -> Data {
        // Check if `AsymmetricKeyAlgorithm` supports a `SecKeyAlgorithm` and if the algorithm is supported to decrypt with a given private key.
        guard let secKeyAlgorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(privateKey, .decrypt, secKeyAlgorithm) else {
            throw EncryptionError.encryptionAlgorithmNotSupported
        }

        // Check if the cipher text length does not exceed the maximum.
        // e.g. for RSAPKCS the cipher text has the same length as the private key's modulus.
        guard algorithm.isCipherTextLenghtSatisfied(ciphertext, for: privateKey) else {
            throw EncryptionError.cipherTextLenghtNotSatisfied
        }

        // Decrypt the cipher text with a given `SecKeyAlgorithm` and a private key.
        var decryptionError: Unmanaged<CFError>?
        guard let plainText = SecKeyCreateDecryptedData(privateKey, secKeyAlgorithm, ciphertext as CFData, &decryptionError) else {
            throw EncryptionError.decryptingFailed(description: decryptionError?.takeRetainedValue().localizedDescription ?? "No description available.")
        }

        return plainText as Data
    }
}
