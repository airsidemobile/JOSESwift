// swiftlint:disable force_unwrapping
//
//  DataRSAPublicKeyTests.swift
//  Tests
//
//  Created by Daniel Egger on 07.02.18.
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

class DataRSAPublicKeyTests: RSACryptoTestCase {

    func testLeadingZeroDropped() {
        let components = try! publicKeyAlice2048Data.rsaPublicKeyComponents()

        XCTAssertEqual(try! [UInt8](publicKeyAlice2048Data).read(.sequence).read(.integer).first!, 0x00)
        XCTAssertNotEqual([UInt8](components.modulus).first!, 0x00)
    }

    func testpublicKeyAlice2048Modulus() {
        let components = try? publicKeyAlice2048Data.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let modulus = components!.modulus

        XCTAssertEqual(modulus, expectedModulus2048Data)
    }

    func testpublicKeyAlice2048Exponent() {
        let components = try? publicKeyAlice2048Data.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let exponent = components!.exponent

        XCTAssertEqual(exponent, expectedExponentData)
    }

    func testPublicKey4096Modulus() {
        let components = try? publicKey4096Data.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let modulus = components!.modulus

        XCTAssertEqual(modulus, expectedModulus4096Data)
    }

    func testPublicKey4096Exponent() {
        let components = try? publicKey4096Data.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let exponent = components!.exponent

        XCTAssertEqual(exponent, expectedExponentData)
    }

    func testDataFromPublicKeyComponents2048() {
        let components = (expectedModulus2048Data, expectedExponentData)
        let data = try! Data.representing(rsaPublicKeyComponents: components)

        let expectedData = publicKeyAlice2048Data

        XCTAssertEqual(data, expectedData)
    }

    func testDataFromPublicKey4096() {
        let components = (expectedModulus4096Data, expectedExponentData)
        let data = try! Data.representing(rsaPublicKeyComponents: components)

        let expectedData = publicKey4096Data

        XCTAssertEqual(data, expectedData)
    }

}
// swiftlint:enable force_unwrapping
