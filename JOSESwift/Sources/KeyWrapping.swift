//
//  KeyWrapping.swift
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

// Todo: All of this

/// A key management mode in which the content encryption key value is encrypted to the
/// intended recipient using a symmetric key wrapping algorithm.
struct KeyWrapping: KeyManagementMode {
    typealias KeyType = AES.KeyType

    let keyManagementAlgorithm: KeyManagementAlgorithm
    let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    let sharedSymmetricKey: KeyType

    init(keyManagementAlgorithm: KeyManagementAlgorithm, contentEncryptionAlgorithm: ContentEncryptionAlgorithm, sharedSymmetricKey: KeyType) {
        // Todo: Check if algorithm is correct
        self.keyManagementAlgorithm = keyManagementAlgorithm
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.sharedSymmetricKey = sharedSymmetricKey
    }

    func determineContentEncryptionKey() throws -> (contentEncryptionKey: Data, encryptedKey: Data) {
        let contentEncryptionKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)
        // Todo: Fix iv.
        let wrappedContenEncryptionKey = try AES.encrypt(contentEncryptionKey, with: sharedSymmetricKey, using: contentEncryptionAlgorithm, and: Data())

        return (contentEncryptionKey, wrappedContenEncryptionKey)
    }
}
