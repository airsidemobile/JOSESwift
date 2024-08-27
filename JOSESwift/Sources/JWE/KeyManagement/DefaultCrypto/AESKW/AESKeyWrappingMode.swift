//
//  AESKeyWrappingMode.swift
//  JOSESwift
//
//  Created by Daniel Egger on 17.02.20.
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

/// A key management mode in which the content encryption key value is encrypted to the intended recipient using a
/// symmetric key wrapping algorithm.
struct AESKeyWrappingMode {
    typealias KeyType = AES.KeyType

    private let keyManagementAlgorithm: KeyManagementAlgorithm
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    private let sharedSymmetricKey: KeyType

    init(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        sharedSymmetricKey: KeyType
    ) {
        self.keyManagementAlgorithm = keyManagementAlgorithm
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.sharedSymmetricKey = sharedSymmetricKey
    }
}

extension AESKeyWrappingMode: EncryptionKeyManagementMode {
    func determineContentEncryptionKey() throws -> (contentEncryptionKey: Data, encryptedKey: Data) {
        let contentEncryptionKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)

        let encryptedKey = try AES.wrap(
            rawKey: contentEncryptionKey,
            keyEncryptionKey: sharedSymmetricKey,
            algorithm: keyManagementAlgorithm
        )

        return (contentEncryptionKey, encryptedKey)
    }
}

extension AESKeyWrappingMode: DecryptionKeyManagementMode {
    func determineContentEncryptionKey(from encryptedKey: Data) throws -> Data {
        let contentEncryptionKey = try AES.unwrap(
            wrappedKey: encryptedKey,
            keyEncryptionKey: sharedSymmetricKey,
            algorithm: keyManagementAlgorithm
        )

        guard contentEncryptionKey.count == contentEncryptionAlgorithm.keyLength else {
            throw AESError.keyLengthNotSatisfied
        }

        return contentEncryptionKey
    }
}
