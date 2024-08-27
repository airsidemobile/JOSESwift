// swiftlint:disable force_unwrapping
//
//  DirectEncryptionKeyManagementModeTests.swift
//  Tests
//
//  Created by Daniel Egger on 13.02.20.
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

import XCTest
@testable import JOSESwift

class DirectEncryptionKeyManagementModeTests: XCTestCase {
    let sharedSymmetricKey = "secret".data(using: .utf8)!

    func testReturnsSharedSymmeyricKeyAsContentEncryptionKey() throws {
        let header = JWEHeader(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A128CBCHS256)
        let keyEncryption = DirectEncryptionMode(
            keyManagementAlgorithm: .direct,
            sharedSymmetricKey: sharedSymmetricKey
        )

        let context1 = try keyEncryption.determineContentEncryptionKey(with: header)
        let context2 = try keyEncryption.determineContentEncryptionKey(with: header)

        XCTAssertEqual(context1.contentEncryptionKey, sharedSymmetricKey)
        XCTAssertEqual(context1.contentEncryptionKey, context2.contentEncryptionKey)
        XCTAssertEqual(context1.encryptedKey, context2.encryptedKey)
        XCTAssertNil(context1.jweHeader)
        XCTAssertNil(context2.jweHeader)

    }

    func testEncryptedKeyIsEmpty() throws {
        let header = JWEHeader(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256CBCHS512)

        let keyEncryption = DirectEncryptionMode(
            keyManagementAlgorithm: .direct,
            sharedSymmetricKey: sharedSymmetricKey
        )

        let context = try keyEncryption.determineContentEncryptionKey(with: header)

        XCTAssertEqual(context.encryptedKey, Data())
    }
}
// swiftlint:enable force_unwrapping
