//
//  SecKeyRSAPublicKeyConvertibleTests.swift
//  Tests
//
//  Created by Daniel Egger on 06.02.18.
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

class SecKeyRSAPublicKeyConvertibleTests: CryptoTestCase {

    func testPublicKeyModulus() {
        let components = try? publicKey!.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let modulus = components!.modulus

        XCTAssertEqual(modulus, expectedModulusData)
    }

    func testPublicKeyExponent() {
        let components = try? publicKey!.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let exponent = components!.exponent

        XCTAssertEqual(exponent, expectedExponentData)
    }

}
