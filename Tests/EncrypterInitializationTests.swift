//
//  EncrypterInitializationTests.swift
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

class EncrypterInitializationTests: CryptoTestCase {

    @available(*, deprecated)
    func testDeprecatedRSAInitialization() {
        XCTAssertNotNil(
            Encrypter(keyEncryptionAlgorithm: .RSA1_5, keyEncryptionKey: publicKey2048!, contentEncyptionAlgorithm: .A256CBCHS512)
        )
    }

    func testNewRSAInitialization() {
        XCTAssertNotNil(
            Encrypter(keyEncryptionAlgorithm: .RSA1_5, encryptionKey: publicKey2048!, contentEncyptionAlgorithm: .A256CBCHS512)
        )
    }

    func tesItnitializationWrongAlgorithm() {
        XCTAssertNil(
            Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: publicKey2048!, contentEncyptionAlgorithm: .A256CBCHS512)
        )
    }

    func testRSAInitializationWrongKeyType() {
        XCTAssertNil(
            Encrypter(keyEncryptionAlgorithm: .RSA1_5, encryptionKey: Data(), contentEncyptionAlgorithm: .A256CBCHS512)
        )
    }

    func testDirectInitializationWrongKeyType() {
        XCTAssertNil(
            Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: publicKey2048!, contentEncyptionAlgorithm: .A256CBCHS512)
        )
    }
    
}
