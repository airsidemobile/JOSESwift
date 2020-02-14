//
//  RSAKeyManagementModeTests.swift
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

// swiftlint:disable force_unwrapping

import XCTest
@testable import JOSESwift

class RSAKeyManagementModeTests: RSACryptoTestCase {
    let keyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.RSA1_5, .RSAOAEP, .RSAOAEP256]

    func testGeneratesRandomContentEncryptionKeyOnEachCall() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = RSAKeyEncryptionMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A256CBCHS512,
                recipientPublicKey: publicKeyAlice2048!
            )

            let (cek1, _) = try keyEncryption.determineContentEncryptionKey()
            let (cek2, _) = try keyEncryption.determineContentEncryptionKey()

            XCTAssertNotEqual(cek1, cek2)
        }
    }

    func testEncryptsContentEncryptionKey() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = RSAKeyEncryptionMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A256CBCHS512,
                recipientPublicKey: publicKeyAlice2048!
            )

            let (cek, encryptedKey) = try keyEncryption.determineContentEncryptionKey()

            XCTAssertNotEqual(cek, encryptedKey)

            var decryptionError: Unmanaged<CFError>?
            let decryptedKey = SecKeyCreateDecryptedData(
                privateKeyAlice2048!,
                algorithm.secKeyAlgorithm!,
                encryptedKey as CFData,
                &decryptionError
            )

            XCTAssertNil(decryptionError)
            XCTAssertNotNil(decryptedKey)

            XCTAssertEqual(cek, decryptedKey! as Data)
        }
    }

    func testEncryptsContentEncryptionKeyOnlyForProvidedKey() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = RSAKeyEncryptionMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A256CBCHS512,
                recipientPublicKey: publicKeyAlice2048!
            )

            let (cek, encryptedKey) = try keyEncryption.determineContentEncryptionKey()

            XCTAssertNotEqual(cek, encryptedKey)

            var decryptionError: Unmanaged<CFError>?
            let decryptedKey = SecKeyCreateDecryptedData(
                privateKeyBob2048!,
                algorithm.secKeyAlgorithm!,
                encryptedKey as CFData,
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
                let keyEncryption = RSAKeyEncryptionMode(
                    keyManagementAlgorithm: alg,
                    contentEncryptionAlgorithm: enc,
                    recipientPublicKey: publicKeyAlice2048!
                )

                let (cek, _) = try keyEncryption.determineContentEncryptionKey()

                XCTAssertEqual(cek.count, enc.keyLength)
            }
        }
    }
}
