//
//  Decrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 17/10/2017.
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

public struct Decrypter {
    private let keyManagementMode: DecryptionKeyManagementMode

    let keyManagementAlgorithm: KeyManagementAlgorithm
    let contentEncryptionAlgorithm: ContentEncryptionAlgorithm

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
        self.keyManagementAlgorithm = keyManagementAlgorithm
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm

        let mode = keyManagementAlgorithm.makeDecryptionKeyManagementMode(
            contentEncryptionAlgorithm: contentEncryptionAlgorithm,
            decryptionKey: decryptionKey
        )

        guard let keyManagementMode = mode else { return nil }
        self.keyManagementMode = keyManagementMode
    }

    internal func decrypt(_ context: DecryptionContext) throws -> Data {
        guard let alg = context.protectedHeader.keyManagementAlgorithm, alg == keyManagementAlgorithm else {
            throw JWEError.keyManagementAlgorithmMismatch
        }

        guard let enc = context.protectedHeader.contentEncryptionAlgorithm, enc == contentEncryptionAlgorithm else {
            throw JWEError.contentEncryptionAlgorithmMismatch
        }

        let contentEncryptionKey = try keyManagementMode.determineContentEncryptionKey(from: context.encryptedKey)

        let contentDecryptionContext = ContentDecryptionContext(
            ciphertext: context.ciphertext,
            initializationVector: context.initializationVector,
            additionalAuthenticatedData: context.protectedHeader.data().base64URLEncodedData(),
            authenticationTag: context.authenticationTag
        )

        return try contentEncryptionAlgorithm
            .makeContentDecrypter(contentEncryptionKey: contentEncryptionKey)
            .decrypt(decryptionContext: contentDecryptionContext)
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

// MARK: - Deprecated API

extension Decrypter {
    @available(*, deprecated, message: "Use `init?(keyManagementAlgorithm:contentEncryptionAlgorithm:decryptionKey:)` instead")
    public init?<KeyType>(keyDecryptionAlgorithm: AsymmetricKeyAlgorithm, decryptionKey key: KeyType, contentDecryptionAlgorithm: SymmetricKeyAlgorithm) {
        self.init(keyManagementAlgorithm: keyDecryptionAlgorithm, contentEncryptionAlgorithm: contentDecryptionAlgorithm, decryptionKey: key)
    }

    @available(*, deprecated, message: "Use `init?(keyManagementAlgorithm:contentEncryptionAlgorithm:decryptionKey:)` instead")
    public init?<KeyType>(keyDecryptionAlgorithm: AsymmetricKeyAlgorithm, keyDecryptionKey kdk: KeyType, contentDecryptionAlgorithm: SymmetricKeyAlgorithm) {
        self.init(keyDecryptionAlgorithm: keyDecryptionAlgorithm, decryptionKey: kdk, contentDecryptionAlgorithm: contentDecryptionAlgorithm)
    }
}

@available(*, deprecated, message: "This type will be removed with the next major release.")
public struct DecryptionContext {
    let header: JWEHeader
    let encryptedKey: Data
    let initializationVector: Data
    let ciphertext: Data
    let authenticationTag: Data
}

@available(*, deprecated, message: "This type will be removed with the next major release.")
public struct SymmetricDecryptionContext {
    let ciphertext: Data
    let initializationVector: Data
    let additionalAuthenticatedData: Data
    let authenticationTag: Data
}
