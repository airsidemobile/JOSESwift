//
//  AESKeyWrapKeyManagementModeTests.swift
//  Tests
//
//  Created by Daniel Egger on 18.02.20.
//

// swiftlint:disable force_unwrapping

import XCTest
@testable import JOSESwift

class AESKeyWrapKeyManagementModeTests: XCTestCase {
    let keyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.A128KW, .A192KW, .A256KW]

    let symmetricKeys: [KeyManagementAlgorithm: Data] = [
        KeyManagementAlgorithm.A128KW: Data(count: 128 / 8),
        KeyManagementAlgorithm.A192KW: Data(count: 192 / 8),
        KeyManagementAlgorithm.A256KW: Data(count: 256 / 8)
    ]

    func testGeneratesRandomContentEncryptionKeyOnEachCall() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[algorithm]!
            )

            let (cek1, _) = try keyEncryption.determineContentEncryptionKey()
            let (cek2, _) = try keyEncryption.determineContentEncryptionKey()

            XCTAssertNotEqual(cek1, cek2)
        }
    }

    func testFailsForWrongKeySiye() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: Data(count: 10)
            )

            XCTAssertThrowsError(try keyEncryption.determineContentEncryptionKey())
        }
    }

    func testEncryptsContentEncryptionKey() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[algorithm]!
            )

            let (cek, encryptedKey) = try keyEncryption.determineContentEncryptionKey()

            XCTAssertNotEqual(cek, encryptedKey)

            // Todo: Decypt
        }
    }

    func testEncryptsContentEncryptionKeyOnlyForProvidedKey() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[algorithm]!
            )

            let (cek, encryptedKey) = try keyEncryption.determineContentEncryptionKey()

            XCTAssertNotEqual(cek, encryptedKey)

            // Todo: Try to decrypt with wrong key
        }
    }

    func testGeneratesContentEncryptionKeyOfCorrectLength() throws {
        let contentEncryptionAlgorithms: [ContentEncryptionAlgorithm] = [.A128CBCHS256, .A256CBCHS512]

        for alg in keyManagementModeAlgorithms {
            for enc in contentEncryptionAlgorithms {
                let keyEncryption = AESKeyWrappingMode(
                    keyManagementAlgorithm: alg,
                    contentEncryptionAlgorithm: enc,
                    sharedSymmetricKey: symmetricKeys[alg]!
                )

                let (cek, _) = try keyEncryption.determineContentEncryptionKey()

                XCTAssertEqual(cek.count, enc.keyLength)
            }
        }
    }

}
