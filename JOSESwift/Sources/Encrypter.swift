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

public struct EncryptionContext {
    let encryptedKey: Data
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

public struct Encrypter<KeyType> {
    let keyManagementAlgorithm: KeyManagementAlgorithm
    let contentEncryptionAlgorithm: ContentEncryptionAlgorithm

    let keyManagementMode: KeyManagementModeImplementation

    // Todo: parameter naming
    init?(keyEncryptionAlgorithm: KeyManagementAlgorithm, encryptionKey: KeyType, contentEncyptionAlgorithm: ContentEncryptionAlgorithm) {
        self.keyManagementAlgorithm = keyEncryptionAlgorithm
        self.contentEncryptionAlgorithm = contentEncyptionAlgorithm

        guard let keyManagementMode = KeyManagementMode.makeImplementation(keyManagementAlgorithm: keyManagementAlgorithm, contentEncryptionAlgorithm: contentEncryptionAlgorithm, encryptionKey: encryptionKey) else {
            return nil
        }

        self.keyManagementMode = keyManagementMode
    }

    @available(*, deprecated, message: "Use `init?(keyEncryptionAlgorithm:encryptionKey:contentEncyptionAlgorithm:)` instead")
    public init?(keyEncryptionAlgorithm: KeyManagementAlgorithm, keyEncryptionKey kek: KeyType, contentEncyptionAlgorithm: ContentEncryptionAlgorithm) {
        self.init(keyEncryptionAlgorithm: keyEncryptionAlgorithm, encryptionKey: kek, contentEncyptionAlgorithm: contentEncyptionAlgorithm)
    }

    func encrypt(header: JWEHeader, payload: Payload) throws -> EncryptionContext {
        try ensureAlgorithmsMatch(with: header)

        let (contentEncryptionKey, encryptedKey) = try keyManagementMode.determineContentEncryptionKey()

        guard let contentEncryption = ContentEncryption.makeImplementation(contentEncryptionAlgorithm: contentEncryptionAlgorithm, contentEncryptionKey: contentEncryptionKey) else {
            // Todo: Error
            throw JOSESwiftError.compressionFailed
        }

        let contentEncryptionContext = try contentEncryption.encrypt(header: header, payload: payload, with: contentEncryptionKey)

        return EncryptionContext(
            encryptedKey: encryptedKey,
            ciphertext: contentEncryptionContext.ciphertext,
            authenticationTag: contentEncryptionContext.authenticationTag,
            initializationVector: contentEncryptionContext.initializationVector
        )
    }
}

private extension Encrypter {
    func ensureAlgorithmsMatch(with header: JWEHeader) throws {
        guard let alg = header.algorithm, alg == keyManagementAlgorithm else {
            throw JWEError.keyManagementAlgorithmMismatch
        }

        guard let enc = header.encryptionAlgorithm, enc == contentEncryptionAlgorithm else {
            throw JWEError.contentEncryptionAlgorithmMismatch
        }
    }


}
