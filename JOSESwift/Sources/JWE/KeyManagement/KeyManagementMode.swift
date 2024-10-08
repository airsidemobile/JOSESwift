//
//  KeyManagementMode.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
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

public protocol EncryptionKeyManagementMode {
    var algorithm: KeyManagementAlgorithm { get }

    func determineContentEncryptionKey(with header: JWEHeader) throws -> EncryptionKeyManagementModeContext
}

public struct EncryptionKeyManagementModeContext {
    let contentEncryptionKey: Data
    let encryptedKey: Data
    let jweHeader: JWEHeader?
}

public protocol DecryptionKeyManagementMode {
    var algorithm: KeyManagementAlgorithm { get }

    func determineContentEncryptionKey(from encryptedKey: Data, with header: JWEHeader) throws -> Data
}

extension KeyManagementAlgorithm {
    func makeEncryptionKeyManagementMode<KeyType>(
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        encryptionKey: KeyType,
        agreementPartyUInfo: Data? = nil,
        agreementPartyVInfo: Data? = nil,
        pbes2SaltInputLength: Int? = nil
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

            return DirectEncryptionMode(keyManagementAlgorithm: self, sharedSymmetricKey: sharedSymmetricKey)
        case .ECDH_ES, .ECDH_ES_A128KW, .ECDH_ES_A192KW, .ECDH_ES_A256KW:
            guard let recipientPublicKey = cast(encryptionKey, to: ECKeyEncryption.PublicKey.self) else {
                return nil
            }

            return ECKeyEncryption.EncryptionMode(keyManagementAlgorithm: self,
                                                  contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                                                  recipientPublicKey: recipientPublicKey,
                                                  agreementPartyUInfo: agreementPartyUInfo ?? Data(),
                                                  agreementPartyVInfo: agreementPartyVInfo ?? Data())
        case .PBES2_HS256_A128KW, .PBES2_HS384_A192KW, .PBES2_HS512_A256KW:
            guard let password = cast(encryptionKey, to: PBES2KeyEncryptionMode.KeyType.self) else {
                return nil
            }

            return PBES2KeyEncryptionMode(
                keyManagementAlgorithm: self,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                password: password,
                pbes2SaltInputLength: pbes2SaltInputLength
            )
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

            return DirectEncryptionMode(keyManagementAlgorithm: self, sharedSymmetricKey: sharedSymmetricKey)
        case .ECDH_ES, .ECDH_ES_A128KW, .ECDH_ES_A192KW, .ECDH_ES_A256KW:
            guard let recipientPrivateKey = cast(decryptionKey, to: ECKeyEncryption.PrivateKey.self) else {
                return nil
            }

            return ECKeyEncryption.DecryptionMode(keyManagementAlgorithm: self,
                                                  contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                                                  recipientPrivateKey: recipientPrivateKey
            )
        case .PBES2_HS256_A128KW, .PBES2_HS384_A192KW, .PBES2_HS512_A256KW:
            guard let password = cast(decryptionKey, to: PBES2KeyEncryptionMode.KeyType.self) else {
                return nil
            }

            return PBES2KeyEncryptionMode(
                keyManagementAlgorithm: self,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                password: password
            )
        }
    }
}

private func cast<GivenType, ExpectedType>(
    _ something: GivenType,
    to _: ExpectedType.Type
) -> ExpectedType? {
    // A conditional downcast to the CoreFoundation type SecKey will always succeed.
    // Therefore we perform runtime type checking to guarantee that the given encryption key's type
    // matches the type that the respective key management mode expects.
    return (type(of: something) is ExpectedType.Type) ? (something as! ExpectedType) : nil
}
