//
//  AESDecrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 09.11.17.
//  Refactored by Marius Tamulis on 2019-03-12.
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

/// A `KeyDecrypter` for symmetric algorithm to decrypt (unwrap) content encryption key with an `AES` algorithm.
internal struct AESKeyDecrypter: KeyDecrypter {
    typealias KeyType = AES.KeyType

    private var symmetricAlgorithm: SymmetricKeyAlgorithm
    var algorithm: KeyAlgorithm {
        return symmetricAlgorithm
    }

    private var symmetricKey: KeyType?
    var key: Any? {
        return symmetricKey
    }

    init(algorithm: SymmetricKeyAlgorithm, symmetricKey: KeyType? = nil) {
        self.symmetricAlgorithm = algorithm
        self.symmetricKey = symmetricKey
    }

    func decrypt(_ ciphertext: Data) throws -> Data {
        guard let symmetricKey = symmetricKey else {
            throw JWEError.keyNotSetOrInvalid
        }
        
        guard symmetricAlgorithm.checkKeyLength(for: symmetricKey) else {
            throw JWEError.keyLengthNotSatisfied
        }

        // For symmetric key crypto default (rfc) initial value or vector is used.
        let iv = symmetricAlgorithm.defaultInitialValue
        // Decrypt the cipher text with a symmetric decryption key, a symmetric algorithm and the initialization vector, return the plaintext if no error occured.
        let plaintext = try AES.decrypt(cipherText: ciphertext, with: symmetricKey, using: symmetricAlgorithm, and: iv)

        return plaintext
    }
}

/// A `ContentDecrypter` to decrypt a cipher text (content) with an `AES` algorithm.
internal struct AESContentDecrypter: ContentDecrypter {
    typealias KeyType = AES.KeyType

    private var symmetricAlgorithm: SymmetricContentAlgorithm
    var algorithm: ContentAlgorithm {
        return symmetricAlgorithm
    }

    private var symmetricKey: KeyType?
    var contentKey: Any? {
        return symmetricKey
    }

    init(algorithm: SymmetricContentAlgorithm, contentKey: KeyType? = nil) {
        self.symmetricAlgorithm = algorithm
        self.symmetricKey = contentKey
    }

    func decrypt(_ context: ContentDecryptionContext, with contentKey: Any? = nil) throws -> Data {
        guard let combinedKey = (contentKey == nil) ? symmetricKey : contentKey as? KeyType else {
            // Key not nil but cannot be cast to correct type
            throw JWEError.keyNotSetOrInvalid
        }

        // Check if the key length contains both HMAC key and the actual symmetric key.
        guard symmetricAlgorithm.checkKeyLength(for: combinedKey) else {
            throw JWEError.keyLengthNotSatisfied
        }

        // Get the two keys for the HMAC and the symmetric encryption.
        let keys = try symmetricAlgorithm.retrieveKeys(from: combinedKey)
        let hmacKey = keys.hmacKey
        let decryptionKey = keys.encryptionKey

        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
        var concatData = context.additionalAuthenticatedData
        concatData.append(context.initializationVector)
        concatData.append(context.ciphertext)
        concatData.append(context.additionalAuthenticatedData.getByteLengthAsOctetHexData())

        // Calculate the HMAC for the concatenated input data and compare it with the reference authentication tag.
        let hmacOutput = HMAC.calculate(from: concatData, with: hmacKey, using: symmetricAlgorithm.hmacAlgorithm)

        guard context.authenticationTag == symmetricAlgorithm.authenticationTag(for: hmacOutput) else {
            throw JWEError.hmacNotAuthenticated
        }

        // Decrypt the cipher text with a symmetric decryption key, a symmetric algorithm and the initialization vector, return the plaintext if no error occured.
        let plaintext = try AES.decrypt(cipherText: context.ciphertext, with: decryptionKey, using: symmetricAlgorithm, and: context.initializationVector)

        return plaintext
    }
}
