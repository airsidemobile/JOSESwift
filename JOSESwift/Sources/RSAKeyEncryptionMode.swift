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
    let encryptionKey: KeyType

    init(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        recipientPublicKey: KeyType
    ) {
        self.keyManagementAlgorithm = keyManagementAlgorithm
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        encryptionKey = recipientPublicKey
    }

    init(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        recipientPrivateKey: KeyType
    ) {
        self.keyManagementAlgorithm = keyManagementAlgorithm
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        encryptionKey = recipientPrivateKey
    }
}

extension RSAKeyEncryptionMode: EncryptionKeyManagementMode {
    func determineContentEncryptionKey() throws -> (contentEncryptionKey: Data, encryptedKey: Data) {
        let contentEncryptionKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)
        let encryptedKey = try RSA.encrypt(contentEncryptionKey, with: encryptionKey, and: keyManagementAlgorithm)

        return (contentEncryptionKey, encryptedKey)
    }
}

extension RSAKeyEncryptionMode: DecryptionKeyManagementMode {
    func determineContentEncryptionKey(from encryptedKey: Data) throws -> Data {
        // Generate a random CEK to substitue in case we fail to decrypt the CEK.
        // This is to prevent the MMA (Million Message Attack) against RSA.
        // For detailed information, please refer to RFC-3218 (https://tools.ietf.org/html/rfc3218#section-2.3.2),
        // RFC-5246 (https://tools.ietf.org/html/rfc5246#appendix-F.1.1.2),
        // and http://www.ietf.org/mail-archive/web/jose/current/msg01832.html.
        let randomContentEncryptionKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)

        guard
            let contentEncryptionKey = try? RSA.decrypt(encryptedKey, with: encryptionKey, and: keyManagementAlgorithm),
            contentEncryptionKey.count == contentEncryptionAlgorithm.keyLength
        else {
            // Todo: Check where to generate the random key
            // Todo: Only use MMA mitigation for RSA1_5
            return randomContentEncryptionKey
        }

        return contentEncryptionKey
    }
}
