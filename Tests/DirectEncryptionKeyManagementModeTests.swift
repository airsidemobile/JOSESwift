// swiftlint:disable force_unwrapping
//
//  DirectEncryptionKeyManagementModeTests.swift
//  Tests
//
//  Created by Daniel Egger on 13.02.20.
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

import XCTest
@testable import JOSESwift

class DirectEncryptionKeyManagementModeTests: XCTestCase {
    let sharedSymmetricKey = "secret".data(using: .utf8)!

    func testReturnsSharedSymmeyricKeyAsContentEncryptionKey() throws {
        let keyEncryption = DirectEncryptionMode(sharedSymmetricKey: sharedSymmetricKey)

        let (cek1, _) = try keyEncryption.determineContentEncryptionKey()
        let (cek2, _) = try keyEncryption.determineContentEncryptionKey()

        XCTAssertEqual(cek1, sharedSymmetricKey)
        XCTAssertEqual(cek1, cek2)

    }

    func testEncryptedKeyIsEmpty() throws {
        let keyEncryption = DirectEncryptionMode(sharedSymmetricKey: sharedSymmetricKey)

        let (_, encryptedKey) = try keyEncryption.determineContentEncryptionKey()

        XCTAssertEqual(encryptedKey, Data())
    }
}
