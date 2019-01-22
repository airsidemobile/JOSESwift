//
//  EncrypterDecrypterInitializationTests.swift
//  Tests
//
//  Created by Daniel Egger on 17.07.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
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
    func testEncrypterDeprecatedRSAInitialization() {
        XCTAssertNotNil(
            Encrypter(keyEncryptionAlgorithm: .RSA1_5, keyEncryptionKey: publicKeyAlice2048!, contentEncyptionAlgorithm: .A256CBCHS512)
        )
    }

    func testEncrypterNewRSAInitialization() {
        XCTAssertNotNil(
            Encrypter(keyEncryptionAlgorithm: .RSA1_5, encryptionKey: publicKeyAlice2048!, contentEncyptionAlgorithm: .A256CBCHS512)
        )
    }

    func testEncrypterRSAInitializationWrongAlgorithm() {
        XCTAssertNil(
            Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: publicKeyAlice2048!, contentEncyptionAlgorithm: .A256CBCHS512)
        )
    }

    func testEncrypterRSAInitializationWrongKeyType() {
        XCTAssertNil(
            Encrypter(keyEncryptionAlgorithm: .RSA1_5, encryptionKey: Data(), contentEncyptionAlgorithm: .A256CBCHS512)
        )
    }

    func testEncrypterDirectInitializationWrongKeyType() {
        XCTAssertNil(
            Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: publicKeyAlice2048!, contentEncyptionAlgorithm: .A256CBCHS512)
        )
    }

    @available(*, deprecated)
    func testDecrypterDeprecatedRSAInitialization() {
        XCTAssertNotNil(
            Decrypter(keyDecryptionAlgorithm: .RSA1_5, keyDecryptionKey: privateKeyAlice2048!, contentDecryptionAlgorithm: .A256CBCHS512)
        )
    }

    func testDecrypterNewRSAInitialization() {
        XCTAssertNotNil(
            Decrypter(keyDecryptionAlgorithm: .RSA1_5, decryptionKey: privateKeyAlice2048!, contentDecryptionAlgorithm: .A256CBCHS512)
        )
    }

    func testDecrypterRSAInitializationWrongAlgorithm() {
        XCTAssertNil(
            Decrypter(keyDecryptionAlgorithm: .direct, decryptionKey: privateKeyAlice2048!, contentDecryptionAlgorithm: .A256CBCHS512)
        )
    }

    func testDecrypterRSAInitializationWrongKeyType() {
        XCTAssertNil(
            Decrypter(keyDecryptionAlgorithm: .RSA1_5, decryptionKey: Data(), contentDecryptionAlgorithm: .A256CBCHS512)
        )
    }

    func testDecrypterDirectInitializationWrongKeyType() {
        XCTAssertNil(
            Decrypter(keyDecryptionAlgorithm: .direct, decryptionKey: privateKeyAlice2048!, contentDecryptionAlgorithm: .A256CBCHS512)
        )
    }
    
}
