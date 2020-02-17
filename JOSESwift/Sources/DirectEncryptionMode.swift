//
//  DirectEncryptionMode.swift
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

/// A key management mode in which the content encryption key value used is a given secret symmetric key value shared
/// between the parties. For direct encryption the JWE encrypted key is the empty octet sequence.
struct DirectEncryptionMode {
    typealias KeyType = Data

    private let sharedSymmetricKey: KeyType

    init(sharedSymmetricKey: KeyType) {
        self.sharedSymmetricKey = sharedSymmetricKey
    }
}

extension DirectEncryptionMode: EncryptionKeyManagementMode {
    func determineContentEncryptionKey() throws -> (contentEncryptionKey: Data, encryptedKey: Data) {
        return (sharedSymmetricKey, KeyType())
    }
}

extension DirectEncryptionMode: DecryptionKeyManagementMode {
    func determineContentEncryptionKey(from encryptedKey: Data) throws -> Data {
        guard encryptedKey == Data() else {
            throw JOSESwiftError.decryptingFailed(description: "Direct encryption does not expect an encrypted key.")
        }

        return sharedSymmetricKey
    }
}
