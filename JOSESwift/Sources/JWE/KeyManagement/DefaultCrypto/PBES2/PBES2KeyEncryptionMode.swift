//
//  PBES2KeyEncryptionMode.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 08.12.23.
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

struct PBES2KeyEncryptionMode {
    typealias KeyType = String

    static let defaultPBES2SaltInputLength = 8
    static let defaultPBES2IterationCount = 1_000

    private let keyManagementAlgorithm: KeyManagementAlgorithm
    private let contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    private let password: KeyType

    let pbes2SaltInputLength: Int

    init(
        keyManagementAlgorithm: KeyManagementAlgorithm,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm,
        password: KeyType,
        pbes2SaltInputLength: Int? = nil
    ) {
        self.keyManagementAlgorithm = keyManagementAlgorithm
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.password = password

        // A Salt Input value containing 8 or more octets MUST be used.
        // See [RFC-7518, 4.8.1.1](https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.1).
        if let pbes2SaltInputLength, pbes2SaltInputLength > Self.defaultPBES2SaltInputLength {
            self.pbes2SaltInputLength = pbes2SaltInputLength
        } else {
            self.pbes2SaltInputLength = Self.defaultPBES2SaltInputLength
        }
    }
}

extension PBES2KeyEncryptionMode: EncryptionKeyManagementMode {
    var algorithm: KeyManagementAlgorithm {
        keyManagementAlgorithm
    }

    func determineContentEncryptionKey(with header: JWEHeader) throws -> EncryptionKeyManagementModeContext {
        var updatedHeader = header

        let saltInput = try SecureRandom.generate(count: pbes2SaltInputLength)
        updatedHeader.p2s = saltInput

        // A minimum iteration count of 1000 is RECOMMENDED (but not required).
        // See [RFC-7518, 4.8.1.2](https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2).
        let iterationCount = header.p2c ?? Self.defaultPBES2IterationCount
        updatedHeader.p2c = iterationCount

        guard let keyWrapAlgorithm = keyManagementAlgorithm.keyWrapAlgorithm else {
            throw PBES2Error.unknownOrUnsupportedAlgorithm
        }

        let derivedKey = try PBES2.deriveWrappingKey(password: password, algorithm: keyManagementAlgorithm, saltInput: saltInput, iterationCount: iterationCount)

        let contentKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)
        let encryptedKey = try AES.wrap(rawKey: contentKey, keyEncryptionKey: derivedKey, algorithm: keyWrapAlgorithm)

        return .init(
            contentEncryptionKey: contentKey,
            encryptedKey: encryptedKey,
            jweHeader: updatedHeader
        )
    }
}

extension PBES2KeyEncryptionMode: DecryptionKeyManagementMode {
    func determineContentEncryptionKey(from encryptedKey: Data, with header: JWEHeader) throws -> Data {
        guard let saltInput = header.p2s else {
            throw HeaderParsingError.requiredHeaderParameterMissing(parameter: "p2s")
        }
        guard let iterationCount = header.p2c else {
            throw HeaderParsingError.requiredHeaderParameterMissing(parameter: "p2c")
        }
        guard let keyWrapAlgorithm = keyManagementAlgorithm.keyWrapAlgorithm else {
            throw PBES2Error.unknownOrUnsupportedAlgorithm
        }
        let derivedKey = try PBES2.deriveWrappingKey(password: password, algorithm: keyManagementAlgorithm, saltInput: saltInput, iterationCount: iterationCount)
        return try AES.unwrap(wrappedKey: encryptedKey, keyEncryptionKey: derivedKey, algorithm: keyWrapAlgorithm)
    }
}
