//
//  AESDecrypter.swift
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

/// A `SymmetricDecrypter` to decrypt a cipher text with an `AES` algorithm.
internal struct AESDecrypter: SymmetricDecrypter {
    typealias KeyType = AES.KeyType

    let algorithm: SymmetricKeyAlgorithm
    let symmetricKey: KeyType?

    init(algorithm: SymmetricKeyAlgorithm, symmetricKey: KeyType? = nil) {
        self.algorithm = algorithm
        self.symmetricKey = symmetricKey
    }

    func decrypt(_ context: SymmetricDecryptionContext, with symmetricKey: Data) throws -> Data {
        // Check if the key length contains both HMAC key and the actual symmetric key.
        guard algorithm.checkKeyLength(for: symmetricKey) else {
            throw JWEError.keyLengthNotSatisfied
        }

        // Get the two keys for the HMAC and the symmetric encryption.
        let keys = try algorithm.retrieveKeys(from: symmetricKey)
        let hmacKey = keys.hmacKey
        let decryptionKey = keys.encryptionKey

        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
        var concatData = context.additionalAuthenticatedData
        concatData.append(context.initializationVector)
        concatData.append(context.ciphertext)
        concatData.append(context.additionalAuthenticatedData.getByteLengthAsOctetHexData())

        // Calculate the HMAC for the concatenated input data and compare it with the reference authentication tag.
        let hmacOutput = HMAC.calculate(from: concatData, with: hmacKey, using: algorithm.hmacAlgorithm)

        guard context.authenticationTag == algorithm.authenticationTag(for: hmacOutput) else {
            throw JWEError.hmacNotAuthenticated
        }

        // Decrypt the cipher text with a symmetric decryption key, a symmetric algorithm and the initialization vector, return the plaintext if no error occured.
        let plaintext = try AES.decrypt(cipherText: context.ciphertext, with: decryptionKey, using: algorithm, and: context.initializationVector)

        return plaintext
    }
}
