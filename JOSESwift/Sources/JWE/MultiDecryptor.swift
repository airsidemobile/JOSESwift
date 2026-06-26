//
//  MultiDecryptor.swift
//  JOSESwift
//
//  Created by Prem Eide on 05/12/2025.
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

/// A `JWEDecrypter` that selects the recipient matching a given key and decrypts it.
///
/// Supports `ECPrivateKey` (ECDH-ES) and `SymmetricKey` (AES key wrap, direct). RSA
/// recipients need a `SecKey` and are decrypted with `Decrypter` directly.
public struct MultiDecryptor: JWEDecrypter {
    private let jwk: JWK

    public init(jwk: JWK) {
        self.jwk = jwk
    }

    public func decrypt(
        header: JWEHeader,
        encryptedKey: Base64URL,
        initializationVector: Base64URL,
        ciphertext: Base64URL,
        authenticationTag: Base64URL,
        additionalAuthenticatedData: Data
    ) throws -> Data {
        let (recipientEncryptedKey, effectiveHeader) = try resolveRecipient(
            protectedHeader: header,
            encryptedKey: encryptedKey
        )

        guard let keyManagementAlgorithm = effectiveHeader.keyManagementAlgorithm else {
            throw JWEObjectJSONError.missingKeyManagementAlgorithm
        }
        guard let contentEncryptionAlgorithm = effectiveHeader.contentEncryptionAlgorithm else {
            throw JWEObjectJSONError.missingContentEncryptionAlgorithm
        }
        guard let decrypter = makeDecrypter(
            keyManagementAlgorithm: keyManagementAlgorithm,
            contentEncryptionAlgorithm: contentEncryptionAlgorithm
        ) else {
            throw JWEObjectJSONError.couldNotConstructDecrypter
        }

        return try decrypter.decrypt(
            header: effectiveHeader,
            encryptedKey: recipientEncryptedKey,
            initializationVector: initializationVector,
            ciphertext: ciphertext,
            authenticationTag: authenticationTag,
            additionalAuthenticatedData: additionalAuthenticatedData
        )
    }

    /// Resolves the recipient's encrypted key and effective header for this key.
    ///
    /// With multiple recipients (`encryptedKey` is a `{"recipients": [...]}` object) the
    /// match is by `kid`; otherwise the single flattened recipient is used.
    private func resolveRecipient(
        protectedHeader: JWEHeader,
        encryptedKey: Base64URL
    ) throws -> (Base64URL, JWEHeader) {
        guard let recipients = Self.decodeRecipients(from: encryptedKey) else {
            // Flattened serialization: the protected header carries `alg`.
            return (encryptedKey, protectedHeader)
        }

        let thumbprint = try? jwk.thumbprint()
        for recipient in recipients {
            guard let unprotectedHeader = recipient.unprotectedHeader,
                  let effectiveHeader = try? protectedHeader.join(unprotectedHeader) else {
                continue
            }
            if matches(header: effectiveHeader, thumbprint: thumbprint) {
                return (recipient.encryptedKey, effectiveHeader)
            }
        }

        throw JWEObjectJSONError.recipientNotFound
    }

    /// Decodes a `{"recipients": [...]}` object, or returns `nil` for a single recipient.
    private static func decodeRecipients(from encryptedKey: Base64URL) -> [Recipient]? {
        guard let data = try? encryptedKey.decode(),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let recipientsArray = json["recipients"] as? [[String: Any]] else {
            return nil
        }
        return try? recipientsArray.map(Recipient.parse)
    }

    /// Whether the key matches the recipient `kid` (by JWK thumbprint or the key's `kid`).
    private func matches(header: JWEHeader, thumbprint: String?) -> Bool {
        guard let recipientKeyID = header.kid else {
            return false
        }
        if let thumbprint = thumbprint, recipientKeyID == thumbprint {
            return true
        }
        if let configuredKeyID = jwk["kid"], recipientKeyID == configuredKeyID {
            return true
        }
        return false
    }

    /// Builds a `Decrypter` from this decrypter's key for the resolved algorithms.
    private func makeDecrypter(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    ) -> Decrypter? {
        switch jwk {
        case let ecPrivateKey as ECPrivateKey:
            return Decrypter(
                keyManagementAlgorithm: keyManagementAlgorithm,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                decryptionKey: ecPrivateKey
            )
        case let symmetricKey as SymmetricKey:
            guard let keyData = try? symmetricKey.converted(to: Data.self) else {
                return nil
            }
            return Decrypter(
                keyManagementAlgorithm: keyManagementAlgorithm,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                decryptionKey: keyData
            )
        // RSA needs a `SecKey`; JOSESwift's `RSAPrivateKey` JWK lacks the CRT params and
        // a `SecKey` conversion, so RSA recipients aren't supported here yet.
        default:
            return nil
        }
    }
}
