//
//  AESCBCEncryption.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//
//  ---------------------------------------------------------------------------
//  Copyright 2020 Airside Mobile Inc.
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

struct AESCBCEncryption {
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    private let contentEncryptionKey: Data

    init(contentEncryptionAlgorithm: ContentEncryptionAlgorithm, contentEncryptionKey: Data) {
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.contentEncryptionKey = contentEncryptionKey
    }

    func encrypt(_ plaintext: Data, additionalAuthenticatedData: Data) throws -> ContentEncryptionContext {
        let iv = try SecureRandom.generate(count: contentEncryptionAlgorithm.initializationVectorLength)

        let keys = try contentEncryptionAlgorithm.retrieveKeys(from: contentEncryptionKey)
        let hmacKey = keys.hmacKey
        let encryptionKey = keys.encryptionKey

        let ciphertext = try AES.encrypt(plaintext, with: encryptionKey, using: contentEncryptionAlgorithm, and: iv)

        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
        var concatData = additionalAuthenticatedData
        concatData.append(iv)
        concatData.append(ciphertext)
        concatData.append(additionalAuthenticatedData.getByteLengthAsOctetHexData())

        let hmac = try HMAC.calculate(from: concatData, with: hmacKey, using: contentEncryptionAlgorithm.hmacAlgorithm)
        let authenticationTag = contentEncryptionAlgorithm.authenticationTag(for: hmac)

        return ContentEncryptionContext(
            ciphertext: ciphertext,
            authenticationTag: authenticationTag,
            initializationVector: iv
        )
    }

    func decrypt(
        _ ciphertext: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data,
        authenticationTag: Data
    ) throws -> Data {
        // Check if the key length contains both HMAC key and the actual symmetric key.
        guard contentEncryptionAlgorithm.checkKeyLength(for: contentEncryptionKey) else {
            throw JWEError.keyLengthNotSatisfied
        }

        // Get the two keys for the HMAC and the symmetric encryption.
        let keys = try contentEncryptionAlgorithm.retrieveKeys(from: contentEncryptionKey)
        let hmacKey = keys.hmacKey
        let decryptionKey = keys.encryptionKey

        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
        var concatData = additionalAuthenticatedData
        concatData.append(initializationVector)
        concatData.append(ciphertext)
        concatData.append(additionalAuthenticatedData.getByteLengthAsOctetHexData())

        // Calculate the HMAC for the concatenated input data and compare it with the reference authentication tag.
        let hmacOutput = try HMAC.calculate(
            from: concatData,
            with: hmacKey,
            using: contentEncryptionAlgorithm.hmacAlgorithm
        )

        guard
            authenticationTag.timingSafeCompare(with: contentEncryptionAlgorithm.authenticationTag(for: hmacOutput))
        else {
            throw JWEError.hmacNotAuthenticated
        }

        // Decrypt the cipher text with a symmetric decryption key, a symmetric algorithm and the initialization vector,
        // return the plaintext if no error occured.
        let plaintext = try AES.decrypt(
            cipherText: ciphertext,
            with: decryptionKey,
            using: contentEncryptionAlgorithm,
            and: initializationVector
        )

        return plaintext
    }
}

extension AESCBCEncryption: ContentEncrypter {
    func encrypt(header: JWEHeader, payload: Payload) throws -> ContentEncryptionContext {
        let plaintext = payload.data()
        let additionalAuthenticatedData = header.data().base64URLEncodedData()

        return try encrypt(plaintext, additionalAuthenticatedData: additionalAuthenticatedData)
    }
}

extension AESCBCEncryption: ContentDecrypter {
    func decrypt(decryptionContext: ContentDecryptionContext) throws -> Data {
        return try decrypt(
            decryptionContext.ciphertext,
            initializationVector: decryptionContext.initializationVector,
            additionalAuthenticatedData: decryptionContext.additionalAuthenticatedData,
            authenticationTag: decryptionContext.authenticationTag
        )
    }
}
