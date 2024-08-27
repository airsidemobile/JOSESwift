//
//  JWKSetCollectionTests.swift
//  Tests
//
//  Created by Daniel Egger on 15.02.18.
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

class JWKSetCollectionTests: XCTestCase {

    let rsaKeys = [
        RSAPublicKey(modulus: "modulus0", exponent: "exponent0"),
        RSAPublicKey(modulus: "modulus1", exponent: "exponent1"),
        RSAPublicKey(modulus: "modulus2", exponent: "exponent2")
    ]

    func testFowardIterating() {
        let set = JWKSet(keys: rsaKeys)

        for (index, key) in set.enumerated() {
            XCTAssertEqual((key as! RSAPublicKey).modulus, rsaKeys[index].modulus)
            XCTAssertEqual((key as! RSAPublicKey).exponent, rsaKeys[index].exponent)
        }
    }

    func testCreationFromArrayLiteral() {
        let set: JWKSet = [
            RSAPublicKey(modulus: "modulus0", exponent: "exponent0"),
            RSAPublicKey(modulus: "modulus1", exponent: "exponent1"),
            RSAPublicKey(modulus: "modulus2", exponent: "exponent2")
        ]

        for (index, key) in set.enumerated() {
            XCTAssertEqual((key as! RSAPublicKey).modulus, rsaKeys[index].modulus)
            XCTAssertEqual((key as! RSAPublicKey).exponent, rsaKeys[index].exponent)
        }
    }

    func testSubscriptAccess() {
        let set =  JWKSet(keys: rsaKeys)

        XCTAssertEqual((set[1] as! RSAPublicKey).modulus, rsaKeys[1].modulus)
        XCTAssertEqual((set[0] as! RSAPublicKey).modulus, rsaKeys[0].modulus)
        XCTAssertEqual((set[2] as! RSAPublicKey).modulus, rsaKeys[2].modulus)
    }

    func testIndices() {
        let set = JWKSet(keys: rsaKeys)

        XCTAssertEqual(set.startIndex, rsaKeys.startIndex)
        XCTAssertEqual(set.endIndex, rsaKeys.endIndex)
        XCTAssertEqual(set.index(after: 1), rsaKeys.index(after: 1))
    }

    func testCount() {
        var set = JWKSet(keys: rsaKeys)

        XCTAssertEqual(set.count, 3)
        XCTAssertFalse(set.isEmpty)

        set = JWKSet(keys: [])

        XCTAssertEqual(set.count, 0)
        XCTAssertTrue(set.isEmpty)
    }

}
