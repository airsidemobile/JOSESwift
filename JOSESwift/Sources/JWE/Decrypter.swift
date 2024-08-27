//
//  Decrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 17/10/2017.
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

public struct Decrypter {
    private let keyManagementMode: DecryptionKeyManagementMode
    private let contentDecrypter: ContentDecrypter

    /// Constructs a decrypter that can be used to decrypt a JWE.
    ///
    /// - Parameters:
    ///   - keyManagementAlgorithm: The algorithm that was used to encrypt the content encryption key.
    ///   - contentEncryptionAlgorithm: The algorithm that was used to encrypt the JWE's payload.
    ///   - decryptionKey: The key used to perform the decryption. The function of the key depends on the chosen key
    ///                    management algorithm.
    ///     - For _key encryption_ it is the private key (`SecKey`) of the recipient to which the JWE was encrypted.
    ///     - For _direct encryption_ it is the secret symmetric key (`Data`) shared between the sender and the
    ///       recipient.
    public init?<KeyType>(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        decryptionKey: KeyType
    ) {
        let mode = keyManagementAlgorithm.makeDecryptionKeyManagementMode(
            contentEncryptionAlgorithm: contentEncryptionAlgorithm,
            decryptionKey: decryptionKey
        )

        guard let keyManagementMode = mode else { return nil }
        self.keyManagementMode = keyManagementMode

        let decrypter = try? contentEncryptionAlgorithm.makeContentDecrypter()
        guard let contentDecrypter = decrypter else { return nil }
        self.contentDecrypter = contentDecrypter
    }

    /// Constructs an decrypter used to decrypt a JWE.
    ///
    /// - Parameters:
    ///   - keyManagementMode: A custom key management implementation.
    ///   - contentEncrypter: A custom content decryption implementation.
    ///
    ///   It is the implementors responsibility to ensure compliance with the necessary specifications.
    /// - Returns: A fully initialized `Decrypter`.
    public init(
        customKeyManagementMode keyManagementMode: DecryptionKeyManagementMode,
        customContentDecrypter contentDecrypter: ContentDecrypter
    ) {
        self.keyManagementMode = keyManagementMode
        self.contentDecrypter = contentDecrypter
    }

    internal func decrypt(_ context: DecryptionContext) throws -> Data {
        guard
            let headerAlg = context.protectedHeader.keyManagementAlgorithm, headerAlg == keyManagementMode.algorithm
        else {
            throw JWEError.keyManagementAlgorithmMismatch
        }

        guard
            let headerEnc = context.protectedHeader.contentEncryptionAlgorithm, headerEnc == contentDecrypter.algorithm
        else {
            throw JWEError.contentEncryptionAlgorithmMismatch
        }

        let contentEncryptionKey = try keyManagementMode.determineContentEncryptionKey(
            from: context.encryptedKey,
            with: context.protectedHeader
        )

        let contentDecryptionContext = ContentDecryptionContext(
            ciphertext: context.ciphertext,
            initializationVector: context.initializationVector,
            additionalAuthenticatedData: context.protectedHeader.data().base64URLEncodedData(),
            authenticationTag: context.authenticationTag,
            contentEncryptionKey: contentEncryptionKey
        )

        return try contentDecrypter.decrypt(decryptionContext: contentDecryptionContext)
    }
}

extension Decrypter {
    struct DecryptionContext {
        let protectedHeader: JWEHeader
        let encryptedKey: Data
        let initializationVector: Data
        let ciphertext: Data
        let authenticationTag: Data
    }
}
