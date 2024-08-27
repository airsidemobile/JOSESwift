//
//  RSAKeyManagementModeTests.swift
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

// swiftlint:disable force_unwrapping

import XCTest
@testable import JOSESwift

class RSAKeyManagementModeTests: RSACryptoTestCase {
    let keyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.RSA1_5, .RSAOAEP, .RSAOAEP256]

    func testGeneratesRandomContentEncryptionKeyOnEachCall() throws {
        for algorithm in keyManagementModeAlgorithms {
            let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512)

            let keyEncryption = RSAKeyEncryption.EncryptionMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A256CBCHS512,
                recipientPublicKey: publicKeyAlice2048!
            )

            let context1 = try keyEncryption.determineContentEncryptionKey(with: header)
            let context2 = try keyEncryption.determineContentEncryptionKey(with: header)

            XCTAssertNotEqual(context1.contentEncryptionKey, context2.contentEncryptionKey)
            XCTAssertNotEqual(context1.encryptedKey, context2.encryptedKey)
            XCTAssertNil(context1.jweHeader)
            XCTAssertNil(context2.jweHeader)
        }
    }

    func testEncryptsContentEncryptionKey() throws {
        for algorithm in keyManagementModeAlgorithms {
            let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512)

            let keyEncryption = RSAKeyEncryption.EncryptionMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A256CBCHS512,
                recipientPublicKey: publicKeyAlice2048!
            )

            let context = try keyEncryption.determineContentEncryptionKey(with: header)

            XCTAssertNotEqual(context.contentEncryptionKey, context.encryptedKey)

            var decryptionError: Unmanaged<CFError>?
            let decryptedKey = SecKeyCreateDecryptedData(
                privateKeyAlice2048!,
                algorithm.secKeyAlgorithm!,
                context.encryptedKey as CFData,
                &decryptionError
            )

            XCTAssertNil(decryptionError)
            XCTAssertNotNil(decryptedKey)

            XCTAssertEqual(context.contentEncryptionKey, decryptedKey! as Data)
        }
    }

    func testEncryptsContentEncryptionKeyOnlyForProvidedKey() throws {
        for algorithm in keyManagementModeAlgorithms {
            let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512)

            let keyEncryption = RSAKeyEncryption.EncryptionMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A256CBCHS512,
                recipientPublicKey: publicKeyAlice2048!
            )

            let context = try keyEncryption.determineContentEncryptionKey(with: header)

            XCTAssertNotEqual(context.contentEncryptionKey, context.encryptedKey)

            var decryptionError: Unmanaged<CFError>?
            let decryptedKey = SecKeyCreateDecryptedData(
                privateKeyBob2048!,
                algorithm.secKeyAlgorithm!,
                context.encryptedKey as CFData,
                &decryptionError
            )

            XCTAssertNotNil(decryptionError)
            XCTAssertNil(decryptedKey)
        }
    }

    func testGeneratesContentEncryptionKeyOfCorrectLength() throws {
        let contentEncryptionAlgorithms: [ContentEncryptionAlgorithm] = [.A128CBCHS256, .A256CBCHS512]

        for alg in keyManagementModeAlgorithms {
            for enc in contentEncryptionAlgorithms {
                let header = JWEHeader(keyManagementAlgorithm: alg, contentEncryptionAlgorithm: enc)

                let keyEncryption = RSAKeyEncryption.EncryptionMode(
                    keyManagementAlgorithm: alg,
                    contentEncryptionAlgorithm: enc,
                    recipientPublicKey: publicKeyAlice2048!
                )

                let context = try keyEncryption.determineContentEncryptionKey(with: header)

                XCTAssertEqual(context.contentEncryptionKey.count, enc.keyLength)
            }
        }
    }

    func testDecryptsContentEncryptionKey() throws {
        let contentEncryptionAlgorithm = ContentEncryptionAlgorithm.A128CBCHS256
        for algorithm in keyManagementModeAlgorithms {
            let header = JWEHeader(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm
            )

            let keyDecryption = RSAKeyEncryption.DecryptionMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                recipientPrivateKey: privateKeyAlice2048!
            )

            let contentEncryptionKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)
            let encryptedKey = try RSA.encrypt(
                contentEncryptionKey,
                with: publicKeyAlice2048!,
                and: algorithm
            )

            let decryptedKey = try keyDecryption.determineContentEncryptionKey(from: encryptedKey, with: header)

            XCTAssertEqual(contentEncryptionKey, decryptedKey)
        }
    }

    // MMA mitigation.
    // For detailed information, please refer to RFC-3218 (https://tools.ietf.org/html/rfc3218#section-2.3.2)
    func testDoesNotThrowForDecryptionError() throws {
        let contentEncryptionAlgorithm = ContentEncryptionAlgorithm.A128CBCHS256
        for algorithm in keyManagementModeAlgorithms {
            let header = JWEHeader(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm
            )

            let keyDecryption = RSAKeyEncryption.DecryptionMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                recipientPrivateKey: privateKeyBob2048!
            )

            let contentEncryptionKey = try SecureRandom.generate(count: contentEncryptionAlgorithm.keyLength)
            let encryptedKey = try RSA.encrypt(
                contentEncryptionKey,
                with: publicKeyAlice2048!,
                and: algorithm
            )

            XCTAssertNoThrow(try keyDecryption.determineContentEncryptionKey(from: encryptedKey, with: header))
        }
    }

    // MMA mitigation.
    // For detailed information, please refer to RFC-3218 (https://tools.ietf.org/html/rfc3218#section-2.3.2)
    func testGeneratesRandomContentEncryptionKeyForMalformedEncryptedKey() throws {
        let contentEncryptionAlgorithm = ContentEncryptionAlgorithm.A128CBCHS256
        for algorithm in keyManagementModeAlgorithms {
            let header = JWEHeader(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm
            )

            let keyDecryption = RSAKeyEncryption.DecryptionMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                recipientPrivateKey: privateKeyAlice2048!
            )

            let encryptedKey = Data(count: algorithm.maxMessageLength(for: publicKeyAlice2048!)! - 10)

            let randomContentEncryptionKey1 = try keyDecryption.determineContentEncryptionKey(
                from: encryptedKey, with: header
            )
            let randomContentEncryptionKey2 = try keyDecryption.determineContentEncryptionKey(
                from: encryptedKey,
                with: header
            )

            XCTAssertNotEqual(randomContentEncryptionKey1, randomContentEncryptionKey2)
        }
    }
}
// swiftlint:enable force_unwrapping
