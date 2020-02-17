// swiftlint:disable force_unwrapping
//
//  EncrypterDecrypterInitializationTests.swift
//  Tests
//
//  Created by Daniel Egger on 17.07.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
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

class EncrypterDecrypterInitializationTests: RSACryptoTestCase {

    @available(*, deprecated)
    func testEncrypterDeprecated1RSAInitialization() {
        for algorithm in KeyManagementAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }

            XCTAssertNotNil(
                Encrypter(keyEncryptionAlgorithm: algorithm, keyEncryptionKey: publicKeyAlice2048!, contentEncyptionAlgorithm: .A256CBCHS512)
            )
        }
    }

    @available(*, deprecated)
    func testEncrypterDeprecated2RSAInitialization() {
        for algorithm in KeyManagementAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }

            XCTAssertNotNil(
                Encrypter(keyEncryptionAlgorithm: algorithm, encryptionKey: publicKeyAlice2048!, contentEncyptionAlgorithm: .A256CBCHS512)
            )
        }
    }

    func testEncrypterNewRSAInitialization() {
        for algorithm in KeyManagementAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }

            XCTAssertNotNil(
                Encrypter(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: publicKeyAlice2048!)!
            )
        }
    }

    func testEncrypterRSAKeyInitializationWrongAlgorithm() {
        XCTAssertNil(
            Encrypter(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: publicKeyAlice2048!)
        )
    }

    func testEncrypterRSAAlgorithmInitializationWrongKeyType() {
        XCTAssertNil(
            Encrypter(keyManagementAlgorithm: .RSA1_5, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: Data())
        )
    }

    func testEncrypterDirectInitializationWrongKeyType() {
        XCTAssertNil(
            Encrypter(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: publicKeyAlice2048!)
        )
    }

    @available(*, deprecated)
    func testDecrypterDeprecatedRSAInitialization() {
        for algorithm in KeyManagementAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }

            XCTAssertNotNil(
                Decrypter(keyDecryptionAlgorithm: algorithm, keyDecryptionKey: privateKeyAlice2048!, contentDecryptionAlgorithm: .A256CBCHS512)
            )
        }
    }

    @available(*, deprecated)
    func testDecrypterDeprecated1RSAInitialization() {
        for algorithm in KeyManagementAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }

            XCTAssertNotNil(
                Decrypter(keyDecryptionAlgorithm: algorithm, keyDecryptionKey: privateKeyAlice2048!, contentDecryptionAlgorithm: .A256CBCHS512)
            )
        }
    }

    @available(*, deprecated)
    func testDecrypterDeprecated2RSAInitialization() {
        for algorithm in KeyManagementAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }

            XCTAssertNotNil(
                Decrypter(keyDecryptionAlgorithm: algorithm, decryptionKey: privateKeyAlice2048!, contentDecryptionAlgorithm: .A256CBCHS512)
            )
        }
    }

    func testDecrypterNewRSAInitialization() {
        for algorithm in KeyManagementAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }

            XCTAssertNotNil(
                Decrypter(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512, decryptionKey: privateKeyAlice2048!)
            )
        }
    }

    func testDecrypterRSAInitializationWrongAlgorithm() {
        XCTAssertNil(
            Decrypter(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256CBCHS512, decryptionKey: privateKeyAlice2048!)
        )
    }

    func testDecrypterRSAInitializationWrongKeyType() {
        XCTAssertNil(
            Decrypter(keyManagementAlgorithm: .RSA1_5, contentEncryptionAlgorithm: .A256CBCHS512, decryptionKey: Data())
        )
    }

    func testDecrypterDirectInitializationWrongKeyType() {
        XCTAssertNil(
            Decrypter(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256CBCHS512, decryptionKey: privateKeyAlice2048!)
        )
    }

}
