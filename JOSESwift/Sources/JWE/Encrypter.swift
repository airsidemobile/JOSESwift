//
//  Encrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 13/10/2017.
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

public struct Encrypter {
    private let keyManagementMode: EncryptionKeyManagementMode
    private let contentEncrypter: ContentEncrypter

    /// Constructs an encrypter that can be used to encrypt a JWE.
    ///
    /// - Parameters:
    ///   - keyManagementAlgorithm: The algorithm used to encrypt the content encryption key.
    ///   - contentEncryptionAlgorithm: The algorithm used to encrypt the JWE's payload.
    ///   - encryptionKey: The key used to perform the encryption. The function of the key depends on the chosen key
    ///                    management algorithm.
    ///     - For _key encryption_ it is the public key (`SecKey`) of the recipient to which the JWE should be
    ///       encrypted.
    ///     - For _direct encryption_ it is the secret symmetric key (`Data`) shared between the sender and the
    ///       recipient.
    public init?<KeyType>(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        encryptionKey: KeyType,
        agreementPartyUInfo: Data? = nil,
        agreementPartyVInfo: Data? = nil,
        pbes2SaltInputLength: Int? = nil
    ) {
        let mode = keyManagementAlgorithm.makeEncryptionKeyManagementMode(
            contentEncryptionAlgorithm: contentEncryptionAlgorithm,
            encryptionKey: encryptionKey,
            agreementPartyUInfo: agreementPartyUInfo,
            agreementPartyVInfo: agreementPartyVInfo,
            pbes2SaltInputLength: pbes2SaltInputLength
        )
        guard let keyManagementMode = mode else { return nil }
        self.keyManagementMode = keyManagementMode

        let encrypter = try? contentEncryptionAlgorithm.makeContentEncrypter()
        guard let contentEncrypter = encrypter else { return nil }
        self.contentEncrypter = contentEncrypter
    }

    /// Constructs an encrypter used to encrypt a JWE.
    ///
    /// - Parameters:
    ///   - keyManagementMode: A custom key management implementation.
    ///   - contentEncrypter: A custom content encryption implementation.
    ///
    ///   It is the implementors responsibility to ensure compliance with the necessary specifications.
    /// - Returns: A fully initialized `Encrypter`.
    public init(
        customKeyManagementMode keyManagementMode: EncryptionKeyManagementMode,
        customContentEncrypter contentEncrypter: ContentEncrypter
    ) {
        self.keyManagementMode = keyManagementMode
        self.contentEncrypter = contentEncrypter
    }

    internal func encrypt(header: JWEHeader, payload: Payload) throws -> EncryptionContext {
        guard let headerAlg = header.keyManagementAlgorithm, headerAlg == keyManagementMode.algorithm else {
            throw JWEError.keyManagementAlgorithmMismatch
        }

        guard let headerEnc = header.contentEncryptionAlgorithm, headerEnc == contentEncrypter.algorithm else {
            throw JWEError.contentEncryptionAlgorithmMismatch
        }

        let keyManagementContext = try keyManagementMode.determineContentEncryptionKey(with: header)

        let updatedHeader = if let updatedHeader = keyManagementContext.jweHeader {
            updatedHeader
        } else {
            header
        }

        let contentEncryptionContext = try contentEncrypter.encrypt(
            headerData: updatedHeader.data(),
            payload: payload,
            contentEncryptionKey: keyManagementContext.contentEncryptionKey
        )

        return EncryptionContext(
            jweHeader: updatedHeader,
            encryptedKey: keyManagementContext.encryptedKey,
            ciphertext: contentEncryptionContext.ciphertext,
            authenticationTag: contentEncryptionContext.authenticationTag,
            initializationVector: contentEncryptionContext.initializationVector
        )
    }
}

extension Encrypter {
    struct EncryptionContext {
        let jweHeader: JWEHeader
        let encryptedKey: Data
        let ciphertext: Data
        let authenticationTag: Data
        let initializationVector: Data
    }
}
