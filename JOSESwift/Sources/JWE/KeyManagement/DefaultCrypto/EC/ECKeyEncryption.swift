//
//  ECKeyEncryption.swift
//  JOSESwift
//
//  Created by Mikael Rucinsky on 07.12.20.
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

/// recipient using an asymmetric ECDH encryption algorithm. The resulting ciphertext is the JWE encrypted key.
enum ECKeyEncryption {
    typealias KeyType = EC.KeyType
    typealias PrivateKey = EC.PrivateKey
    typealias PublicKey = EC.PublicKey

    struct EncryptionMode {
        private let keyManagementAlgorithm: KeyManagementAlgorithm
        private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
        private let recipientPublicKey: PublicKey
        private let agreementPartyUInfo: Data
        private let agreementPartyVInfo: Data
        private let options: [String: Any]

        init(
            keyManagementAlgorithm: KeyManagementAlgorithm,
            contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
            recipientPublicKey: PublicKey,
            agreementPartyUInfo: Data,
            agreementPartyVInfo: Data,
            options: [String: Any] = [:]
        ) {
            self.keyManagementAlgorithm = keyManagementAlgorithm
            self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
            self.recipientPublicKey = recipientPublicKey
            self.agreementPartyUInfo = agreementPartyUInfo
            self.agreementPartyVInfo = agreementPartyVInfo
            self.options = options
        }
    }

    struct DecryptionMode {
        private let keyManagementAlgorithm: KeyManagementAlgorithm
        private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
        private let recipientPrivateKey: PrivateKey

        init(
            keyManagementAlgorithm: KeyManagementAlgorithm,
            contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
            recipientPrivateKey: PrivateKey
        ) {
            self.keyManagementAlgorithm = keyManagementAlgorithm
            self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
            self.recipientPrivateKey = recipientPrivateKey
        }
    }
}

extension ECKeyEncryption.EncryptionMode: EncryptionKeyManagementMode {
    var algorithm: KeyManagementAlgorithm {
        keyManagementAlgorithm
    }

    func determineContentEncryptionKey(with jweHeader: JWEHeader) throws -> EncryptionKeyManagementModeContext {
        let ecEncryption = try EC.encryptionContextFor(recipientPublicKey,
                                           algorithm: keyManagementAlgorithm,
                                           encryption: contentEncryptionAlgorithm,
                                           header: jweHeader,
                                           options: options)

        guard let updatedJweHeader = JWEHeader(ecEncryption.jweHeaderData) else {
            throw ECError.wrapKeyFail

        }

        return .init(
            contentEncryptionKey: ecEncryption.contentEncryptionKey,
            encryptedKey: ecEncryption.encryptedKey,
            jweHeader: updatedJweHeader
        )
    }
}

extension ECKeyEncryption.DecryptionMode: DecryptionKeyManagementMode {
    var algorithm: KeyManagementAlgorithm {
        keyManagementAlgorithm
    }

    func determineContentEncryptionKey(from encryptedKey: Data, with header: JWEHeader) throws -> Data {

        let randomContentEncryptionKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)

        let decryptedKey = try EC.decrypt(encryptedKey,
                                           privateKey: recipientPrivateKey,
                                           algorithm: keyManagementAlgorithm,
                                           encryption: contentEncryptionAlgorithm,
                                           header: header)

        guard decryptedKey.count == contentEncryptionAlgorithm.keyLength else { return randomContentEncryptionKey }

        return decryptedKey
    }
}
