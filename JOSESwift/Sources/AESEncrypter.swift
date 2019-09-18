//
//  AESEncrypter.swift
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

/// A `KeyEncrypter` for symmetric algorithm to encrypt (wrap) content encryption key with an `AES` algorithm.
internal struct AESKeyEncrypter: KeyEncrypter {
    typealias KeyType = AES.KeyType

    private var symmetricKey: KeyType?
    var key: Any? {
        return symmetricKey
    }

    private var symmetricAlgorithm: SymmetricKeyAlgorithm
    var algorithm: KeyAlgorithm {
        return symmetricAlgorithm
    }

    init(algorithm: SymmetricKeyAlgorithm, symmetricKey: KeyType? = nil) {
        self.symmetricAlgorithm = algorithm
        self.symmetricKey = symmetricKey
    }
    
    func encrypt(_ plaintext: Data) throws -> Data {
        guard let symmetricKey = self.symmetricKey else {
            throw AESError.encryptingFailed(description: "Encryption key is not set")
        }
        
        return try encrypt(plaintext, with: symmetricKey).ciphertext
    }

    func encrypt(_ plaintext: Data, with symmetricKey: KeyType) throws -> SymmetricEncryptionContext {
        // For symmetric (shared) key encryption default (rfc) IV is used.
        //
        // "This section defines the specifics of encrypting a JWE CEK with the
        // Advanced Encryption Standard (AES) Key Wrap Algorithm [RFC3394] using
        // the default initial value specified in Section 2.2.3.1 of that
        // document."
        let iv = symmetricAlgorithm.defaultInitialValue

        // Encrypt the plaintext with a symmetric encryption key, a symmetric encryption algorithm and an initialization vector.
        let ciphertext = try AES.encrypt(plaintext: plaintext, with: symmetricKey, using: symmetricAlgorithm, and: iv)

        return SymmetricEncryptionContext(
            ciphertext: ciphertext,
            authenticationTag: Data(),
            initializationVector: iv
        )
    }
}

/// A `ContentEncrypter` to encrypt plaintext (content) with an `AES` algorithm.
internal struct AESContentEncrypter: ContentEncrypter {
    typealias KeyType = AES.KeyType

    private var symmetricKey: KeyType?
    var contentKey: Any? {
        return symmetricKey
    }

    private var symmetricAlgorithm: SymmetricContentAlgorithm
    var algorithm: ContentAlgorithm {
        return symmetricAlgorithm
    }

    init(algorithm: SymmetricContentAlgorithm, contentKey: KeyType? = nil) {
        self.symmetricAlgorithm = algorithm
        self.symmetricKey = contentKey
    }

    func encrypt(_ plaintext: Data, with symmetricKey: KeyType, additionalAuthenticatedData: Data) throws -> SymmetricEncryptionContext {
        // Generate random intitialization vector.
        let iv = try SecureRandom.generate(count: algorithm.initializationVectorLength)

        // Get the two keys for the HMAC and the symmetric encryption.
        let keys = try symmetricAlgorithm.retrieveKeys(from: symmetricKey)
        let hmacKey = keys.hmacKey
        let encryptionKey = keys.encryptionKey

        // Encrypt the plaintext with a symmetric encryption key, a symmetric encryption algorithm and an initialization vector.
        let cipherText = try AES.encrypt(plaintext: plaintext, with: encryptionKey, using: algorithm, and: iv)

        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
        var concatData = additionalAuthenticatedData
        concatData.append(iv)
        concatData.append(cipherText)
        concatData.append(additionalAuthenticatedData.getByteLengthAsOctetHexData())

        // Calculate the HMAC with the concatenated input data, the HMAC key and the HMAC algorithm.
        let hmacOutput = try HMAC.calculate(from: concatData, with: hmacKey, using: symmetricAlgorithm.hmacAlgorithm)
        let authenticationTag = symmetricAlgorithm.authenticationTag(for: hmacOutput)

        return SymmetricEncryptionContext(
            ciphertext: cipherText,
            authenticationTag: authenticationTag,
            initializationVector: iv
        )
    }
}
