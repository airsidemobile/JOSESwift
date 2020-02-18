//
//  AESKeyWrapKeyManagementModeTests.swift
//  Tests
//
//  Created by Daniel Egger on 18.02.20.
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

// swiftlint:disable force_unwrapping

import XCTest
import CommonCrypto
@testable import JOSESwift

extension AESError: Equatable {
    public static func == (lhs: AESError, rhs: AESError) -> Bool {
        switch (lhs, rhs) {
        case (.invalidAlgorithm, .invalidAlgorithm):
            return true
        case (.keyLengthNotSatisfied, .keyLengthNotSatisfied):
            return true
        case (.encryptingFailed(description: _), .encryptingFailed(description: _)):
            return true
        case (.decryptingFailed(description: _), .decryptingFailed(description: _)):
            return true
        default:
            return false
        }
    }
}

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

    func testFailsForWrongKeySize() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: Data(count: 10)
            )

            XCTAssertThrowsError(try keyEncryption.determineContentEncryptionKey())
        }
    }

    func testEncryptingFailsForWrongAlgorithm() throws {
        let rsaKeyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.RSA1_5, .RSAOAEP, .RSAOAEP256]
        for algorithm in rsaKeyManagementModeAlgorithms {
            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[.A128KW]!
            )

            XCTAssertThrowsError(try keyEncryption.determineContentEncryptionKey(), "Invalid algorithm") { error in
                XCTAssertEqual(error as! AESError, AESError.invalidAlgorithm)
            }
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

            let decryptedKey = ccAESKeyUnwrap(
                wrappedKey: encryptedKey,
                keyEncryptionKey: symmetricKeys[algorithm]!,
                iv: Data(bytes: CCrfc3394_iv, count: CCrfc3394_ivLen)
            )

            XCTAssertEqual(decryptedKey.data, cek)
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

            let wrongKey = Data(repeating: 1, count: symmetricKeys[algorithm]!.count)

            let decryptedKey = ccAESKeyUnwrap(
                wrappedKey: encryptedKey,
                keyEncryptionKey: wrongKey,
                iv: Data(bytes: CCrfc3394_iv, count: CCrfc3394_ivLen)
            )

            XCTAssertNotEqual(decryptedKey.data, cek)
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

    func testDecryptingFailsForWrongAlgorithm() throws {
        let rsaKeyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.RSA1_5, .RSAOAEP, .RSAOAEP256]
        for algorithm in rsaKeyManagementModeAlgorithms {
            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[.A128KW]!
            )

            XCTAssertThrowsError(
                try keyEncryption.determineContentEncryptionKey(from: Data()), "Invalid algorithm"
            ) { error in
                XCTAssertEqual(error as! AESError, AESError.invalidAlgorithm)
            }
        }
    }

    // Test data taken from RFC-3394, 4 (https://tools.ietf.org/html/rfc3394#section-4).
    func testDecryptsContentEncryptionKeyAndChecksLengthForContentEncryption() throws {
        let keyEncryption = AESKeyWrappingMode(
            keyManagementAlgorithm: .A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256,
            sharedSymmetricKey: "000102030405060708090A0B0C0D0E0F".hexadecimalToData()!
        )

        XCTAssertThrowsError(
            try keyEncryption.determineContentEncryptionKey(
                from: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5".hexadecimalToData()!
            )
        ) { error in
            XCTAssertEqual(error as! AESError, AESError.keyLengthNotSatisfied)
        }
    }
}

private func ccAESKeyUnwrap(
    wrappedKey: Data,
    keyEncryptionKey: Data,
    iv: Data
) -> (data: Data, status: Int32) {
    let alg = CCWrappingAlgorithm(kCCWRAPAES)

    var rawKeyLength: size_t = CCSymmetricUnwrappedSize(alg, wrappedKey.count)
    var rawKey = Data(count: rawKeyLength)

    let status = rawKey.withUnsafeMutableBytes { rawKeyBytes in
        wrappedKey.withUnsafeBytes { wrappedKeyBytes in
            iv.withUnsafeBytes { ivBytes in
                keyEncryptionKey.withUnsafeBytes { keyEncryptionKeyBytes -> Int32 in
                    guard
                        let rawKeyBytes = rawKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        let wrappedKeyBytes = wrappedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        let ivBytes = ivBytes.bindMemory(to: UInt8.self).baseAddress,
                        let keyEncryptionKeyBytes = keyEncryptionKeyBytes.bindMemory(to: UInt8.self).baseAddress
                        else {
                            return Int32(kCCMemoryFailure)
                    }
                    return CCSymmetricKeyUnwrap(
                        alg,
                        ivBytes, iv.count,
                        keyEncryptionKeyBytes, keyEncryptionKey.count,
                        wrappedKeyBytes, wrappedKey.count,
                        rawKeyBytes, &rawKeyLength
                    )
                }
            }
        }
    }

    if status == kCCSuccess {
        rawKey.removeSubrange(rawKeyLength..<rawKey.count)
    }

    return (rawKey, status)
}
