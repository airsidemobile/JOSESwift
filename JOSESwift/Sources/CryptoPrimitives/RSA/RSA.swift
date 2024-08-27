//
//  RSA.swift
//  JOSESwift
//
//  Created by Carol Capek on 06.02.18.
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
import Security

internal enum RSAError: Error {
    case algorithmNotSupported
    case signingFailed(description: String)
    case verifyingFailed(description: String)
    case plainTextLengthNotSatisfied
    case cipherTextLenghtNotSatisfied
    case encryptingFailed(description: String)
    case decryptingFailed(description: String)
}

fileprivate extension SignatureAlgorithm {
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .RS256:
            return .rsaSignatureMessagePKCS1v15SHA256
        case .RS384:
            return .rsaSignatureMessagePKCS1v15SHA384
        case .RS512:
            return .rsaSignatureMessagePKCS1v15SHA512
        case .PS256:
            if #available(iOS 11.0, *) {
                return .rsaSignatureMessagePSSSHA256
            } else {
                return nil
            }

        case .PS384:
            if #available(iOS 11.0, *) {
                return .rsaSignatureMessagePSSSHA384
            } else {
                return nil
            }

        case .PS512:
            if #available(iOS 11.0, *) {
                return .rsaSignatureMessagePSSSHA512
            } else {
                return nil
            }
        default:
            return nil
        }
    }
}

internal extension KeyManagementAlgorithm {
    /// Mapping of `AsymmetricKeyAlgorithm` to Security Framework's `SecKeyAlgorithm`.
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .RSA1_5:
            return .rsaEncryptionPKCS1
        case .RSAOAEP:
            return .rsaEncryptionOAEPSHA1
        case .RSAOAEP256:
            return .rsaEncryptionOAEPSHA256
        default:
            return nil
        }
    }

    /// This method returns the maximum message length allowed for an `AsymmetricKeyAlgorithm`.
    /// - Parameter publicKey: The publicKey used with the algorithm.
    /// - Returns: The maximum message length allowed for use with the algorithm.
    ///
    /// - RSA1_5: For detailed information about the allowed plain text length for RSAES-PKCS1-v1_5,
    /// please refer to [RFC-3447, Section 7.2](https://tools.ietf.org/html/rfc3447#section-7.2).
    /// - RSAOAEP: For detailed information about the allowed plain text length for RSAES-OAEP,
    /// please refer to [RFC-3447, Section 7.1](https://tools.ietf.org/html/rfc3447#section-7.1).
    /// - RSAOAEP256: For detailed information about the allowed plain text length for RSAES-OAEP-256,
    /// please refer to [RFC-3447, Section 7.1](https://tools.ietf.org/html/rfc3447#section-7.1).
    func maxMessageLength(for publicKey: SecKey) -> Int? {
        let k = SecKeyGetBlockSize(publicKey)
        switch self {
        case .RSA1_5:
            return (k - 11)
        case .RSAOAEP:
            // The maximum plaintext length is based on
            // the hash length of SHA-1 (https://tools.ietf.org/html/rfc3174#section-1).
            let hLen = 160 / 8
            return k - 2 * hLen - 2
        case .RSAOAEP256:
            // The maximum plaintext length is based on
            // the hash length of SHA-256.
            let hLen = 256 / 8
            return (k - 2 * hLen - 2)
        default: return nil
        }
    }
}

fileprivate extension KeyManagementAlgorithm {
    /// Checks if the plain text length does not exceed the maximum
    /// for the chosen algorithm and the corresponding public key.
    /// This length checking is just for usability reasons.
    /// Proper length checking is done in the implementation of iOS'
    /// `SecKeyCreateEncryptedData` and `SecKeyCreateDecryptedData`.
    func isPlainTextLengthSatisfied(_ plainText: Data, for publicKey: SecKey) -> Bool? {
        let mLen = plainText.count

        switch self {
        case .RSA1_5, .RSAOAEP, .RSAOAEP256:
            guard let maxMessageLength = maxMessageLength(for: publicKey) else { return nil }
            return mLen <= maxMessageLength
        default:
            return nil
        }
    }

    /// Checks if the ciphertext length does not exceed the maximum
    /// for the chosen algorithm and the corresponding private key.
    /// This length checking is just for usability reasons.
    /// Proper length checking is done in the implementation of iOS'
    /// `SecKeyCreateEncryptedData` and `SecKeyCreateDecryptedData`.
    func isCipherTextLenghtSatisfied(_ cipherText: Data, for privateKey: SecKey) -> Bool? {
        switch self {
        case .RSA1_5:
            // For detailed information about the allowed cipher length for RSAES-PKCS1-v1_5,
            // please refer to the RFC(https://tools.ietf.org/html/rfc3447#section-7.2.2).
            return cipherText.count == SecKeyGetBlockSize(privateKey)
        case .RSAOAEP, .RSAOAEP256:
            // For detailed information about the allowed cipher length for RSAES-OAEP and RSAES-OAEP-256,
            // please refer to RFC-3447 (https://tools.ietf.org/html/rfc3447#section-7.1.2,
            // https://www.rfc-editor.org/errata_search.php?rfc=3447):
            // The ciphertext to be decrypted is an octet string of length k,
            // where k is the length in octets of the RSA modulus,
            // and k >= 2hLen + 2
            return cipherText.count == SecKeyGetBlockSize(privateKey)
        default:
            return nil
        }
    }
}

internal struct RSA {
    typealias KeyType = SecKey

    ///  Signs input data with a given `RSA` algorithm and the corresponding private key.
    ///
    /// - Parameters:
    ///   - signingInput: The data to sign.
    ///   - privateKey: The private key used by the `SignatureAlgorithm`.
    ///   - algorithm: The algorithm to sign the input data.
    /// - Returns: The signature.
    /// - Throws: `RSAError` if any errors occur while signing the input data.
    static func sign(_ signingInput: Data, with privateKey: KeyType, and algorithm: SignatureAlgorithm) throws -> Data {
        // Check if `SignatureAlgorithm` supports a `SecKeyAlgorithm` and
        // if the algorithm is supported to sign with a given private key.
        guard let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw RSAError.algorithmNotSupported
        }

        // Sign the input with a given `SecKeyAlgorithm` and a private key.
        var signingError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, signingInput as CFData, &signingError) else {
            throw RSAError.signingFailed(
                description: signingError?.takeRetainedValue().localizedDescription ?? "No description available."
            )
        }

        return signature as Data
    }

    /// Verifies input data against a signature with a given `RSA` algorithm and the corresponding public key.
    ///
    /// - Parameters:
    ///   - verifyingInput: The data to verify.
    ///   - signature: The signature to verify against.
    ///   - publicKey: The public key used by the `SignatureAlgorithm`.
    ///   - algorithm: The algorithm to verify the input data.
    /// - Returns: True if the signature is verified, false if it is not verified.
    /// - Throws: `RSAError` if any errors occur while verifying the input data against the signature.
    static func verify(_ verifyingInput: Data, against signature: Data, with publicKey: KeyType, and algorithm: SignatureAlgorithm) throws -> Bool {
        // Check if `SignatureAlgorithm` supports a `SecKeyAlgorithm` and
        // if the algorithm is supported to verify with a given public key.
        guard
            let algorithm = algorithm.secKeyAlgorithm, SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm)
        else {
            throw RSAError.algorithmNotSupported
        }

        // Verify the signature against an input with a given `SecKeyAlgorithm` and a public key.
        var verificationError: Unmanaged<CFError>?
        guard
            SecKeyVerifySignature(
                publicKey, algorithm, verifyingInput as CFData, signature as CFData, &verificationError
            )
        else {
            if let description = verificationError?.takeRetainedValue().localizedDescription {
                throw RSAError.verifyingFailed(description: description)
            }

            return false
        }

        return true
    }

    /// Encrypts a plain text using a given `RSA` algorithm and the corresponding public key.
    ///
    /// - Parameters:
    ///   - plaintext: The plain text to encrypt.
    ///   - publicKey: The public key.
    ///   - algorithm: The algorithm used to encrypt the plain text.
    /// - Returns: The cipher text (encrypted plain text).
    /// - Throws: `EncryptionError` if any errors occur while encrypting the plain text.
    static func encrypt(_ plaintext: Data, with publicKey: KeyType, and algorithm: KeyManagementAlgorithm) throws -> Data {
        // Check if `AsymmetricKeyAlgorithm` supports a `SecKeyAlgorithm` and
        // if the algorithm is supported to encrypt with a given public key.
        guard
            let secKeyAlgorithm = algorithm.secKeyAlgorithm,
            SecKeyIsAlgorithmSupported(publicKey, .encrypt, secKeyAlgorithm)
        else {
            throw RSAError.algorithmNotSupported
        }

        // Check if the plain text length does not exceed the maximum.
        // e.g. for RSA1_5 the plaintext must be 11 bytes smaller than the public key's modulus.
        guard algorithm.isPlainTextLengthSatisfied(plaintext, for: publicKey) == true else {
            throw RSAError.plainTextLengthNotSatisfied
        }

        // Encrypt the plain text with a given `SecKeyAlgorithm` and a public key.
        var encryptionError: Unmanaged<CFError>?
        guard
            let cipherText = SecKeyCreateEncryptedData(publicKey, secKeyAlgorithm, plaintext as CFData, &encryptionError)
        else {
            throw RSAError.encryptingFailed(
                description: encryptionError?.takeRetainedValue().localizedDescription ?? "No description available."
            )
        }

        return cipherText as Data
    }

    /// Decrypts a cipher text using a given `RSA` algorithm and the corresponding private key.
    ///
    /// - Parameters:
    ///   - ciphertext: The cipher text to decrypt.
    ///   - privateKey: The private key.
    ///   - algorithm: The algorithm used to decrypt the cipher text.
    /// - Returns: The plain text.
    /// - Throws: `EncryptionError` if any errors occur while decrypting the cipher text.
    static func decrypt(_ ciphertext: Data, with privateKey: KeyType, and algorithm: KeyManagementAlgorithm) throws -> Data {
        // Check if `AsymmetricKeyAlgorithm` supports a `SecKeyAlgorithm` and
        // if the algorithm is supported to decrypt with a given private key.
        guard
            let secKeyAlgorithm = algorithm.secKeyAlgorithm,
            SecKeyIsAlgorithmSupported(privateKey, .decrypt, secKeyAlgorithm)
        else {
            throw RSAError.algorithmNotSupported
        }

        // Check if the cipher text length does not exceed the maximum.
        // e.g. for RSA1_5 the cipher text has the same length as the private key's modulus.
        guard algorithm.isCipherTextLenghtSatisfied(ciphertext, for: privateKey) == true
        else {
            throw RSAError.cipherTextLenghtNotSatisfied
        }

        // Decrypt the cipher text with a given `SecKeyAlgorithm` and a private key.
        var decryptionError: Unmanaged<CFError>?
        guard
            let plainText = SecKeyCreateDecryptedData(privateKey, secKeyAlgorithm, ciphertext as CFData, &decryptionError)
        else {
            throw RSAError.decryptingFailed(
                description: decryptionError?.takeRetainedValue().localizedDescription ?? "No description available."
            )
        }

        return plainText as Data
    }
}
