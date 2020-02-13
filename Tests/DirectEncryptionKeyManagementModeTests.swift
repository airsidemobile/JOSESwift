// swiftlint:disable force_unwrapping
//
//  DirectEncryptionKeyManagementModeTests.swift
//  Tests
//
//  Created by Daniel Egger on 13.02.20.
//

import XCTest
@testable import JOSESwift

class DirectEncryptionKeyManagementModeTests: XCTestCase {
    let sharedSymmetricKey = "secret".data(using: .utf8)!

    func testReturnsSharedSymmeyricKeyAsContentEncryptionKey() throws {
        let keyEncryption = DirectEncryption(sharedSymmetricKey: sharedSymmetricKey)

        let (cek1, _) = try keyEncryption.determineContentEncryptionKey()
        let (cek2, _) = try keyEncryption.determineContentEncryptionKey()

        XCTAssertEqual(cek1, sharedSymmetricKey)
        XCTAssertEqual(cek1, cek2)

    }

    func testEncryptedKeyIsEmpty() throws {
        let keyEncryption = DirectEncryption(sharedSymmetricKey: sharedSymmetricKey)

        let (_, encryptedKey) = try keyEncryption.determineContentEncryptionKey()

        XCTAssertEqual(encryptedKey, Data())
    }
}
