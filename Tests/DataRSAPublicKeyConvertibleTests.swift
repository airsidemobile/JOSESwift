//
//  DataRSAPublicKeyConvertibleTests.swift
//  Tests
//
//  Created by Daniel Egger on 07.02.18.
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
@testable import SwiftJOSE

class DataRSAPublicKeyConvertibleTests: CryptoTestCase {

    func testLeadingZeroDropped() {
        let (modulus, _) = try! publicKey2048Data.rsaPublicKeyComponents()

        XCTAssertEqual(try! [UInt8](publicKey2048Data).read(.sequence).read(.integer).first!, 0x00)
        XCTAssertNotEqual([UInt8](modulus).first!, 0x00)
    }

    func testPublicKey2048Modulus() {
        let components = try? publicKey2048Data.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let modulus = components!.modulus

        XCTAssertEqual(modulus, expectedModulusData)
    }

    func testPublicKey2048Exponent() {
        let components = try? publicKey2048Data.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let exponent = components!.exponent

        XCTAssertEqual(exponent, expectedExponentData)
    }

    func testPublicKey4096Modulus() {
        let components = try? publicKey4096Data.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let modulus = components!.modulus

        XCTAssertEqual(modulus.base64URLEncodedString(), expectedModulus4096Base64)
    }

    func testPublicKey4096Exponent() {
        let components = try? publicKey4096Data.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let exponent = components!.exponent

        XCTAssertEqual(exponent, expectedExponentData)
    }
    
}
