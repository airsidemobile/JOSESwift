//
//  AESGCMEncryption.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 12.08.22.
//
//  ---------------------------------------------------------------------------
//  Copyright 2022 Airside Mobile Inc.
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

import CryptoKit
import Foundation

struct AESGCMEncryption {
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    private let contentEncryptionKey: Data

    init(contentEncryptionAlgorithm: ContentEncryptionAlgorithm, contentEncryptionKey: Data) {
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.contentEncryptionKey = contentEncryptionKey
    }

    func encrypt(_ plaintext: Data, additionalAuthenticatedData: Data) throws -> ContentEncryptionContext {
        return try encrypt(plaintext, initializationVector: nil, additionalAuthenticatedData: additionalAuthenticatedData)
    }

    func encrypt(_ plaintext: Data, initializationVector: Data?, additionalAuthenticatedData: Data) throws -> ContentEncryptionContext {
        let key = CryptoKit.SymmetricKey(data: contentEncryptionKey)
        let nonce: CryptoKit.AES.GCM.Nonce
        if let initializationVector = initializationVector {
            nonce = try CryptoKit.AES.GCM.Nonce(data: initializationVector)
        } else {
            nonce = CryptoKit.AES.GCM.Nonce()
        }
        let encrypted = try CryptoKit.AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: additionalAuthenticatedData)
        return ContentEncryptionContext(
            ciphertext: encrypted.ciphertext,
            authenticationTag: encrypted.tag,
            initializationVector: encrypted.nonce.withUnsafeBytes({ Data(Array($0)) })
        )
    }

    func decrypt(_ ciphertext: Data, initializationVector: Data, additionalAuthenticatedData: Data, authenticationTag: Data) throws -> Data {
        let key = CryptoKit.SymmetricKey(data: contentEncryptionKey)
        let nonce = try CryptoKit.AES.GCM.Nonce(data: initializationVector)
        let encrypted = try CryptoKit.AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: authenticationTag)
        let decrypted = try CryptoKit.AES.GCM.open(encrypted, using: key, authenticating: additionalAuthenticatedData)
        return decrypted
    }
}

extension AESGCMEncryption: ContentEncrypter {
    func encrypt(header: JWEHeader, payload: Payload) throws -> ContentEncryptionContext {
        let plaintext = payload.data()
        let additionalAuthenticatedData = header.data().base64URLEncodedData()
        return try encrypt(plaintext, additionalAuthenticatedData: additionalAuthenticatedData)
    }
}

extension AESGCMEncryption: ContentDecrypter {
    func decrypt(decryptionContext: ContentDecryptionContext) throws -> Data {
        return try decrypt(
            decryptionContext.ciphertext,
            initializationVector: decryptionContext.initializationVector,
            additionalAuthenticatedData: decryptionContext.additionalAuthenticatedData,
            authenticationTag: decryptionContext.authenticationTag
        )
    }
}
