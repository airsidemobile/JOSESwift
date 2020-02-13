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

protocol KeyManagementMode {
    func determineContentEncryptionKey() throws -> (contentEncryptionKey: Data, encryptedKey: Data)
}

extension KeyManagementAlgorithm {
    private enum KeyManagementModeError: Error {
        case wrongKeyTypeForAlgorithm(algorithm: KeyManagementAlgorithm)
    }

    func makeKeyManagementMode<KeyType>(
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        encryptionKey: KeyType
    ) throws -> KeyManagementMode {
        switch self {
        case .RSA1_5, .RSAOAEP, .RSAOAEP256:
            guard let recipientPublicKey = cast(encryptionKey, to: RSAKeyEncryption.KeyType.self) else {
                throw KeyManagementModeError.wrongKeyTypeForAlgorithm(algorithm: self)
            }

            return RSAKeyEncryption(
                keyManagementAlgorithm: self,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                recipientPublicKey: recipientPublicKey
            )
        case .direct:
            guard let sharedSymmetricKey = cast(encryptionKey, to: DirectEncryption.KeyType.self) else {
                throw KeyManagementModeError.wrongKeyTypeForAlgorithm(algorithm: self)
            }

            return DirectEncryption(sharedSymmetricKey: sharedSymmetricKey)
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
