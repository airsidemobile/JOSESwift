//
//  KeyManaggementMode.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
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

protocol EncryptionKeyManagementMode {
    func determineContentEncryptionKey() throws -> (contentEncryptionKey: Data, encryptedKey: Data)
}

protocol DecryptionKeyManagementMode {
    func determineContentEncryptionKey(from encryptedKey: Data) throws -> Data
}

extension KeyManagementAlgorithm {
    func makeEncryptionKeyManagementMode<KeyType>(
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        encryptionKey: KeyType
    ) -> EncryptionKeyManagementMode? {
        switch self {
        case .RSA1_5, .RSAOAEP, .RSAOAEP256:
            guard let recipientPublicKey = cast(encryptionKey, to: RSAKeyEncryption.KeyType.self) else {
                return nil
            }

            return RSAKeyEncryption.EncryptionMode(
                keyManagementAlgorithm: self,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                recipientPublicKey: recipientPublicKey
            )
        case .A128KW, .A192KW, .A256KW:
            guard let sharedSymmetricKey = cast(encryptionKey, to: AESKeyWrappingMode.KeyType.self) else {
                return nil
            }

            return AESKeyWrappingMode(
                keyManagementAlgorithm: self,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                sharedSymmetricKey: sharedSymmetricKey)
        case .direct:
            guard let sharedSymmetricKey = cast(encryptionKey, to: DirectEncryptionMode.KeyType.self) else {
                return nil
            }

            return DirectEncryptionMode(sharedSymmetricKey: sharedSymmetricKey)
        }
    }

    func makeDecryptionKeyManagementMode<KeyType>(
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        decryptionKey: KeyType
    ) -> DecryptionKeyManagementMode? {
        switch self {
        case .RSA1_5, .RSAOAEP, .RSAOAEP256:
            guard let recipientPrivateKey = cast(decryptionKey, to: RSAKeyEncryption.KeyType.self) else {
                return nil
            }

            return RSAKeyEncryption.DecryptionMode(
                keyManagementAlgorithm: self,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                recipientPrivateKey: recipientPrivateKey
            )
        case .A128KW, .A192KW, .A256KW:
            guard let sharedSymmetricKey = cast(decryptionKey, to: AESKeyWrappingMode.KeyType.self) else {
                return nil
            }

            return AESKeyWrappingMode(
                keyManagementAlgorithm: self,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                sharedSymmetricKey: sharedSymmetricKey
            )
        case .direct:
            guard let sharedSymmetricKey = cast(decryptionKey, to: DirectEncryptionMode.KeyType.self) else {
                return nil
            }

            return DirectEncryptionMode(sharedSymmetricKey: sharedSymmetricKey)
        }
    }
}

private func cast<GivenType, ExpectedType>(
    _ something: GivenType,
    to _: ExpectedType.Type
) -> ExpectedType? {
    // A conditional downcast to the CoreFoundation type SecKey will always succeed.
    // Therfore we perform runtime type checking to guarantee that the given encryption key's type
    // matches the type that the respective key management mode expects.
    return (type(of: something) is ExpectedType.Type) ? (something as! ExpectedType) : nil
}
