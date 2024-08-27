//
//  AESKeyWrapKeyManagementModeTests.swift
//  Tests
//
//  Created by Daniel Egger on 18.02.20.
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
            let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A128CBCHS256)

            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[algorithm]!
            )

            let context1 = try keyEncryption.determineContentEncryptionKey(with: header)
            let context2 = try keyEncryption.determineContentEncryptionKey(with: header)

            XCTAssertNotEqual(context1.contentEncryptionKey, context2.contentEncryptionKey)
            XCTAssertNotEqual(context1.encryptedKey, context2.encryptedKey)
            XCTAssertNil(context1.jweHeader)
            XCTAssertNil(context2.jweHeader)
        }
    }

    func testFailsForWrongKeySize() throws {
        for algorithm in keyManagementModeAlgorithms {
            let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A128CBCHS256)

            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: Data(count: 10)
            )

            XCTAssertThrowsError(try keyEncryption.determineContentEncryptionKey(with: header))
        }
    }

    func testEncryptingFailsForWrongAlgorithm() throws {
        let rsaKeyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.RSA1_5, .RSAOAEP, .RSAOAEP256]
        for algorithm in rsaKeyManagementModeAlgorithms {
            let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A128CBCHS256)

            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[.A128KW]!
            )

            XCTAssertThrowsError(
                try keyEncryption.determineContentEncryptionKey(with: header),
                "Invalid algorithm"
            ) { error in
                XCTAssertEqual(error as! AESError, AESError.invalidAlgorithm)
            }
        }
    }

    func testEncryptsContentEncryptionKey() throws {
        for algorithm in keyManagementModeAlgorithms {
            let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A128CBCHS256)

            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[algorithm]!
            )

            let context = try keyEncryption.determineContentEncryptionKey(with: header)

            XCTAssertNotEqual(context.contentEncryptionKey, context.encryptedKey)

            let decryptedKey = ccAESKeyUnwrap(
                wrappedKey: context.encryptedKey,
                keyEncryptionKey: symmetricKeys[algorithm]!,
                iv: Data(bytes: CCrfc3394_iv, count: CCrfc3394_ivLen)
            )

            XCTAssertEqual(context.contentEncryptionKey, decryptedKey.data)
        }
    }

    func testEncryptsContentEncryptionKeyOnlyForProvidedKey() throws {
        for algorithm in keyManagementModeAlgorithms {
            let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A128CBCHS256)

            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[algorithm]!
            )

            let context = try keyEncryption.determineContentEncryptionKey(with: header)

            XCTAssertNotEqual(context.contentEncryptionKey, context.encryptedKey)

            let wrongKey = Data(repeating: 1, count: symmetricKeys[algorithm]!.count)

            let decryptedKey = ccAESKeyUnwrap(
                wrappedKey: context.encryptedKey,
                keyEncryptionKey: wrongKey,
                iv: Data(bytes: CCrfc3394_iv, count: CCrfc3394_ivLen)
            )

            XCTAssertNotEqual(context.contentEncryptionKey, decryptedKey.data)
        }
    }

    func testGeneratesContentEncryptionKeyOfCorrectLength() throws {
        let contentEncryptionAlgorithms: [ContentEncryptionAlgorithm] = [.A128CBCHS256, .A256CBCHS512]

        for alg in keyManagementModeAlgorithms {
            for enc in contentEncryptionAlgorithms {
                let header = JWEHeader(keyManagementAlgorithm: alg, contentEncryptionAlgorithm: enc)

                let keyEncryption = AESKeyWrappingMode(
                    keyManagementAlgorithm: alg,
                    contentEncryptionAlgorithm: enc,
                    sharedSymmetricKey: symmetricKeys[alg]!
                )

                let context = try keyEncryption.determineContentEncryptionKey(with: header)

                XCTAssertEqual(context.contentEncryptionKey.count, enc.keyLength)
            }
        }
    }

    func testDecryptingFailsForWrongAlgorithm() throws {
        let rsaKeyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.RSA1_5, .RSAOAEP, .RSAOAEP256]
        for algorithm in rsaKeyManagementModeAlgorithms {
            let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A128CBCHS256)

            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[.A128KW]!
            )

            XCTAssertThrowsError(
                try keyEncryption.determineContentEncryptionKey(from: Data(), with: header), "Invalid algorithm"
            ) { error in
                XCTAssertEqual(error as! AESError, AESError.invalidAlgorithm)
            }
        }
    }

    // Test data taken from RFC-3394, 4 (https://tools.ietf.org/html/rfc3394#section-4).
    func testDecryptsContentEncryptionKeyAndChecksLengthForContentEncryption() throws {
        let header = JWEHeader(keyManagementAlgorithm: .A128KW, contentEncryptionAlgorithm: .A128CBCHS256)

        let keyEncryption = AESKeyWrappingMode(
            keyManagementAlgorithm: .A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256,
            sharedSymmetricKey: "000102030405060708090A0B0C0D0E0F".hexadecimalToData()!
        )

        XCTAssertThrowsError(
            try keyEncryption.determineContentEncryptionKey(
                from: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5".hexadecimalToData()!,
                with: header
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
// swiftlint:enable force_unwrapping
