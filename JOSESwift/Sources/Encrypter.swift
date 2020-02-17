//
//  Encrypter.swift
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

public struct Encrypter {
    private let keyManagementMode: EncryptionKeyManagementMode
    private let keyManagementAlgorithm: KeyManagementAlgorithm
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm

    /// Constructs an encrypter that can be used to encrypt a JWE.
    ///
    /// - Parameters:
    ///   - keyManagementAlgorithm: The algorithm used to encrypt the content encryption key.
    ///   - contentEncryptionAlgorithm: The algorithm used to encrypt the JWE's payload.
    ///   - encryptionKey: The key used to perform the encryption. The function of the key depends on the chosen key
    ///                    management algorithm.
    ///     - For _key encryption_ it is the public key of the recipient to which the JWE should be encrypted.
    ///     - For _direct encryption_ it is the secret symmetric key shared between the sender and the recipient.
    public init?<KeyType>(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        encryptionKey: KeyType
    ) {
        self.keyManagementAlgorithm = keyManagementAlgorithm
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm

        let mode = keyManagementAlgorithm.makeEncryptionKeyManagementMode(
            contentEncryptionAlgorithm: contentEncryptionAlgorithm,
            encryptionKey: encryptionKey
        )
        guard let keyManagementMode = mode else { return nil }
        self.keyManagementMode = keyManagementMode
    }

    func encrypt(header: JWEHeader, payload: Payload) throws -> EncryptionContext {
        guard let alg = header.algorithm, alg == keyManagementAlgorithm else {
            throw JWEError.keyManagementAlgorithmMismatch
        }

        guard let enc = header.encryptionAlgorithm, enc == contentEncryptionAlgorithm else {
            throw JWEError.contentEncryptionAlgorithmMismatch
        }

        let (contentEncryptionKey, encryptedKey) = try keyManagementMode.determineContentEncryptionKey()

        let contentEncryptionContext = try contentEncryptionAlgorithm
            .makeContentEncrypter(contentEncryptionKey: contentEncryptionKey)
            .encrypt(header: header, payload: payload)

        return EncryptionContext(
            encryptedKey: encryptedKey,
            ciphertext: contentEncryptionContext.ciphertext,
            authenticationTag: contentEncryptionContext.authenticationTag,
            initializationVector: contentEncryptionContext.initializationVector
        )
    }
}

extension Encrypter {
    struct EncryptionContext {
        let encryptedKey: Data
        let ciphertext: Data
        let authenticationTag: Data
        let initializationVector: Data
    }
}

extension Encrypter {
    @available(*, deprecated, message: "Use `init?(keyManagementAlgorithm:contentEncryptionAlgorithm:encryptionKey:)` instead")
    public init?<KeyType>(keyEncryptionAlgorithm: KeyManagementAlgorithm, encryptionKey: KeyType, contentEncyptionAlgorithm: ContentEncryptionAlgorithm) {
        self.init(keyManagementAlgorithm: keyEncryptionAlgorithm, contentEncryptionAlgorithm: contentEncyptionAlgorithm, encryptionKey: encryptionKey)
    }

    @available(*, deprecated, message: "Use `init?(keyEncryptionAlgorithm:encryptionKey:contentEncyptionAlgorithm:)` instead")
    public init?<KeyType>(keyEncryptionAlgorithm: KeyManagementAlgorithm, keyEncryptionKey kek: KeyType, contentEncyptionAlgorithm: ContentEncryptionAlgorithm) {
        self.init(keyEncryptionAlgorithm: keyEncryptionAlgorithm, encryptionKey: kek, contentEncyptionAlgorithm: contentEncyptionAlgorithm)
    }
}
