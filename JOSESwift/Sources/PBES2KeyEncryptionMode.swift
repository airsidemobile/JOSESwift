//
//  PBES2KeyEncryptionMode.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 08.12.23.
//
//  ---------------------------------------------------------------------------
//  Copyright 2023 Airside Mobile Inc.
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

struct PBES2KeyEncryptionMode {
    typealias KeyType = String

    private let keyManagementAlgorithm: KeyManagementAlgorithm
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    private let password: KeyType

    init(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        password: KeyType
    ) {
        self.keyManagementAlgorithm = keyManagementAlgorithm
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.password = password
    }
}

extension PBES2KeyEncryptionMode: EncryptionKeyManagementMode {
    func determineContentEncryptionKey(for header: JWEHeader) throws -> Data {
        var updatedHeader = header
        let salt = try SecureRandom.generate(count: 16)
        updatedHeader.p2s = salt
        let iterations = header.p2c ?? PBES2.defaultIterationCount
        updatedHeader.p2c = iterations
        guard let keyWrapAlgorithm = keyManagementAlgorithm.keyWrapAlgorithm else {
            throw PBES2Error.unknownOrUnsupportedAlgorithm
        }
        let derivedKey = try PBES2.deriveWrappingKey(password: password, algorithm: keyManagementAlgorithm, salt: salt, iterations: iterations)
        let contentKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)
        let encryptedKey = try AES.wrap(rawKey: contentKey, keyEncryptionKey: derivedKey, algorithm: keyWrapAlgorithm)
        let context = Encrypter.PBES2EncryptionContext(headerData: updatedHeader.headerData, encryptedKey: encryptedKey, contentKey: contentKey)
        let result = try JSONEncoder().encode(context)
        return result
    }
}

extension PBES2KeyEncryptionMode: DecryptionKeyManagementMode {
    func determineContentEncryptionKey(from encryptedKey: Data, header: JWEHeader) throws -> Data {
        guard let salt = header.p2s else {
            throw HeaderParsingError.requiredHeaderParameterMissing(parameter: "p2s")
        }
        guard let iterations = header.p2c else {
            throw HeaderParsingError.requiredHeaderParameterMissing(parameter: "p2c")
        }
        guard let keyWrapAlgorithm = keyManagementAlgorithm.keyWrapAlgorithm else {
            throw PBES2Error.unknownOrUnsupportedAlgorithm
        }
        let derivedKey = try PBES2.deriveWrappingKey(password: password, algorithm: keyManagementAlgorithm, salt: salt, iterations: iterations)
        return try AES.unwrap(wrappedKey: encryptedKey, keyEncryptionKey: derivedKey, algorithm: keyWrapAlgorithm)
    }
}
