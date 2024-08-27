//
//  RSAPublicKeyToDataTests.swift
//  Tests
//
//  Created by Daniel Egger on 12.02.18.
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

import XCTest
@testable import JOSESwift

class RSAPublicKeyToDataTests: RSACryptoTestCase {

    func testpublicKeyAlice2048ToData() {
        let jwk = RSAPublicKey(modulus: expectedModulus2048Base64, exponent: expectedExponentBase64)
        let data = try! jwk.converted(to: Data.self)

        XCTAssertEqual(data, publicKeyAlice2048Data)
    }

    func testPublicKey4096ToData() {
        let jwk = RSAPublicKey(modulus: expectedModulus4096Base64, exponent: expectedExponentBase64)
        let data = try! jwk.converted(to: Data.self)

        XCTAssertEqual(data, publicKey4096Data)
    }

}
