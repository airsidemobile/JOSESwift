//
//  AESEncrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 09.11.17.
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

/// A `SymmetricEncrypter` to encrypt plaintext with an `AES` algorithm.
internal struct AESEncrypter: SymmetricEncrypter {
    typealias KeyType = AES.KeyType

    let algorithm: SymmetricKeyAlgorithm
    let symmetricKey: KeyType?

    init(algorithm: SymmetricKeyAlgorithm, symmetricKey: KeyType? = nil) {
        self.algorithm = algorithm
        self.symmetricKey = symmetricKey
    }

    func encrypt(_ plaintext: Data, with symmetricKey: Data, additionalAuthenticatedData: Data) throws -> SymmetricEncryptionContext {
        // Generate random intitialization vector.
        let iv = try SecureRandom.generate(count: algorithm.initializationVectorLength)

        // Get the two keys for the HMAC and the symmetric encryption.
        let keys = try algorithm.retrieveKeys(from: symmetricKey)
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
        let hmacOutput = HMAC.calculate(from: concatData, with: hmacKey, using: algorithm.hmacAlgorithm)
        let authenticationTag = algorithm.authenticationTag(for: hmacOutput)

        return SymmetricEncryptionContext(
            ciphertext: cipherText,
            authenticationTag: authenticationTag,
            initializationVector: iv
        )
    }
}
