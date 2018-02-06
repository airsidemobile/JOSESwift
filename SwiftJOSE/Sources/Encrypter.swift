//
//  Encrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
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
import IDZSwiftCommonCrypto
import CommonCrypto

public enum EncryptionError: Error, Equatable {
    case encryptionAlgorithmNotSupported
    case keyEncryptionAlgorithmMismatch
    case contentEncryptionAlgorithmMismatch
    case plainTextLengthNotSatisfied
    case cipherTextLenghtNotSatisfied
    case keyLengthNotSatisfied
    case hmacNotAuthenticated
    case encryptingFailed(description: String)
    case decryptingFailed(description: String)

    public static func ==(lhs: EncryptionError, rhs: EncryptionError) -> Bool {
        switch (lhs, rhs) {
        case (.cipherTextLenghtNotSatisfied, .cipherTextLenghtNotSatisfied):
            return true
        case (.plainTextLengthNotSatisfied, .plainTextLengthNotSatisfied):
            return true
        default:
            return false
        }
    }
}

internal protocol AsymmetricEncrypter {
    /// The algorithm used to encrypt plaintext.
    var algorithm: AsymmetricKeyAlgorithm { get }

    /// Initializes an `AsymmetricEncrypter` with a specified algorithm and public key.
    init(algorithm: AsymmetricKeyAlgorithm, publicKey: SecKey)

    /**
     Encrypts a plain text using a given `AsymmetricEncryptionAlgorithm` and the corresponding public key.
     - Parameters:
        - plaintext: The plain text to encrypt.
        - algorithm: The algorithm used to encrypt the plain text.
     
     - Throws:
        - `EncryptionError.encryptionAlgorithmNotSupported`: If the provided algorithm is not supported for encryption.
        - `EncryptionError.plainTextLengthNotSatisfied`: If the plain text length exceeds the allowed maximum.
        - `EncryptionError.encryptingFailed(description: String)`: If the encryption failed with a specific error.
     
     - Returns: The cipher text (encrypted plain text).
     */
    func encrypt(_ plaintext: Data) throws -> Data
}

internal protocol SymmetricEncrypter {
    /// The algorithm used to encrypt plaintext.
    var algorithm: SymmetricKeyAlgorithm { get }

    /// Initializes a `SymmetricEncrypter` with a specified algorithm.
    init(algorithm: SymmetricKeyAlgorithm)

    /**
     Encrypts a plain text using the corresponding symmetric key and additional authenticated data.
     - Parameters:
        - plaintext: The plain text to encrypt.
        - symmetricKey: The key which contains the HMAC and encryption key.
        - additionalAuthenticatedData: The data used for integrity protection. 
     
     - Throws:
        - `EncryptionError.keyLengthNotSatisfied`: If the provided key is not long enough to contain the HMAC and the actual encryption key.
        - `EncryptionError.encryptingFailed(description: String)`: If the encryption failed with a specific error.
     
     - Returns: The a `SymmetricEncryptionContext` containing the ciphertext, the authentication tag and the initialization vector.
     */
    func encrypt(_ plaintext: Data, with symmetricKey: Data, additionalAuthenticatedData: Data) throws -> SymmetricEncryptionContext
}

public struct EncryptionContext {
    let encryptedKey: Data
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

public struct SymmetricEncryptionContext {
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

public struct Encrypter {
    let asymmetric: AsymmetricEncrypter
    let symmetric: SymmetricEncrypter

    public init(keyEncryptionAlgorithm: AsymmetricKeyAlgorithm, keyEncryptionKey kek: SecKey, contentEncyptionAlgorithm: SymmetricKeyAlgorithm) {
        self.asymmetric = CryptoFactory.encrypter(for: keyEncryptionAlgorithm, with: kek)
        self.symmetric = CryptoFactory.encrypter(for: contentEncyptionAlgorithm)
    }

    func encrypt(header: JWEHeader, payload: Payload) throws -> EncryptionContext {
        guard let alg = header.algorithm, alg == asymmetric.algorithm else {
            throw EncryptionError.keyEncryptionAlgorithmMismatch
        }
        guard let enc = header.encryptionAlgorithm, enc == symmetric.algorithm else {
            throw EncryptionError.contentEncryptionAlgorithmMismatch
        }

        let cek = try SecureRandom.generate(count: enc.keyLength())
        let encryptedKey = try asymmetric.encrypt(cek)
        let symmetricContext = try symmetric.encrypt(payload.data(), with: cek, additionalAuthenticatedData: header.data().base64URLEncodedData())

        return EncryptionContext(
            encryptedKey: encryptedKey,
            ciphertext: symmetricContext.ciphertext,
            authenticationTag: symmetricContext.authenticationTag,
            initializationVector: symmetricContext.initializationVector
        )
    }
}
