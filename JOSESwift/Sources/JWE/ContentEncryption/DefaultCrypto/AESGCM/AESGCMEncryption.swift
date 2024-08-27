//
//  AESGCMEncryption.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 12.08.22.
//
//  ---------------------------------------------------------------------------
//  Copyright 2024 Airside Mobile Inc.
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

struct AESGCMEncryption {
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm

    init(contentEncryptionAlgorithm: ContentEncryptionAlgorithm) {
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
    }

    func encrypt(_ plaintext: Data, additionalAuthenticatedData: Data, contentEncryptionKey: Data) throws -> ContentEncryptionContext {
        let iv = try SecureRandom.generate(count: contentEncryptionAlgorithm.initializationVectorLength)
        return try encrypt(plaintext, initializationVector: iv, additionalAuthenticatedData: additionalAuthenticatedData, contentEncryptionKey: contentEncryptionKey)
    }

    func encrypt(_ plaintext: Data, initializationVector: Data, additionalAuthenticatedData: Data, contentEncryptionKey: Data) throws -> ContentEncryptionContext {
        return try AESGCM.encrypt(plaintext: plaintext,
                                  encryptionKey: contentEncryptionKey,
                                  initializationVector: initializationVector,
                                  additionalAuthenticatedData: additionalAuthenticatedData)
    }

    func decrypt(_ ciphertext: Data, initializationVector: Data, additionalAuthenticatedData: Data, authenticationTag: Data, contentEncryptionKey: Data) throws -> Data {
        return try AESGCM.decrypt(cipherText: ciphertext,
                                  decryptionKey: contentEncryptionKey,
                                  initializationVector: initializationVector,
                                  authenticationTag: authenticationTag,
                                  additionalAuthenticatedData: additionalAuthenticatedData)
    }
}

extension AESGCMEncryption: ContentEncrypter, ContentDecrypter {
    var algorithm: ContentEncryptionAlgorithm {
        contentEncryptionAlgorithm
    }

    func encrypt(headerData: Data, payload: Payload, contentEncryptionKey: Data) throws -> ContentEncryptionContext {
        guard contentEncryptionAlgorithm.checkKeyLength(for: contentEncryptionKey) else {
            throw JWEError.keyLengthNotSatisfied
        }

        let plaintext = payload.data()
        let additionalAuthenticatedData = headerData.base64URLEncodedData()

        return try encrypt(plaintext, additionalAuthenticatedData: additionalAuthenticatedData, contentEncryptionKey: contentEncryptionKey)
    }

    func decrypt(decryptionContext: ContentDecryptionContext) throws -> Data {
        guard contentEncryptionAlgorithm.checkKeyLength(for: decryptionContext.contentEncryptionKey) else {
            throw JWEError.keyLengthNotSatisfied
        }

        return try decrypt(
            decryptionContext.ciphertext,
            initializationVector: decryptionContext.initializationVector,
            additionalAuthenticatedData: decryptionContext.additionalAuthenticatedData,
            authenticationTag: decryptionContext.authenticationTag,
            contentEncryptionKey: decryptionContext.contentEncryptionKey
        )
    }
}
