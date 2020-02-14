//
//  RSAKeyEncryptionMode.swift
//  JOSESwift
//
//  Created by Daniel Egger on 13/10/2017.
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

/// A key management mode in which a randomly generated content encryption key value is encrypted to the intended
/// recipient using an asymmetric RSA encryption algorithm. For key encryption the resulting ciphertext is the JWE
/// encrypted key.
struct RSAKeyEncryptionMode {
    typealias KeyType = RSA.KeyType

    let keyManagementAlgorithm: KeyManagementAlgorithm
    let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    let recipientPublicKey: KeyType

    init(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        recipientPublicKey: KeyType
    ) {
        self.keyManagementAlgorithm = keyManagementAlgorithm
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.recipientPublicKey = recipientPublicKey
    }
}

extension RSAKeyEncryptionMode: KeyManagementMode {
    func determineContentEncryptionKey() throws -> (contentEncryptionKey: Data, encryptedKey: Data) {
        let contentEncryptionKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)
        let encryptedKey = try RSA.encrypt(contentEncryptionKey, with: recipientPublicKey, and: keyManagementAlgorithm)

        return (contentEncryptionKey, encryptedKey)
    }
}
