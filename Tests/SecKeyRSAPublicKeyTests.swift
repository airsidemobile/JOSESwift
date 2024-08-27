// swiftlint:disable force_unwrapping
//
//  SecKeyRSAPublicKeyTests.swift
//  Tests
//
//  Created by Daniel Egger on 06.02.18.
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

class SecKeyRSAPublicKeyTests: RSACryptoTestCase {

    func testpublicKeyAlice2048Modulus() {
        let components = try? publicKeyAlice2048!.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let modulus = components!.modulus

        XCTAssertEqual(modulus, expectedModulus2048Data)
    }

    func testpublicKeyAlice2048Exponent() {
        let components = try? publicKeyAlice2048!.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let exponent = components!.exponent

        XCTAssertEqual(exponent, expectedExponentData)
    }

    func testPublicKey4096Modulus() {
        let components = try? publicKey4096!.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let modulus = components!.modulus

        XCTAssertEqual(modulus, expectedModulus4096Data)
    }

    func testPublicKey4096Exponent() {
        let components = try? publicKey4096!.rsaPublicKeyComponents()

        XCTAssertNotNil(components)

        let exponent = components!.exponent

        XCTAssertEqual(exponent, expectedExponentData)
    }

    func testPrivateKeyToPublicComponents() {
        XCTAssertThrowsError(try privateKeyAlice2048!.rsaPublicKeyComponents()) { error in
            XCTAssertEqual(error as? JWKError, JWKError.notAPublicKey)
        }
    }

    func testJWKFrompublicKeyAlice2048() {
        let jwk = try? RSAPublicKey(publicKey: publicKeyAlice2048!)

        XCTAssertNotNil(jwk)

        XCTAssertEqual(jwk!.modulus, expectedModulus2048Base64)
        XCTAssertEqual(jwk!.exponent, expectedExponentBase64)
    }

    func testJWKFromPublicKey4096() {
        let jwk = try? RSAPublicKey(publicKey: publicKey4096!)

        XCTAssertNotNil(jwk)

        XCTAssertEqual(jwk!.modulus, expectedModulus4096Base64)
        XCTAssertEqual(jwk!.exponent, expectedExponentBase64)
    }

    func testpublicKeyAlice2048FromPublicComponents() {
        let components = (expectedModulus2048Data, expectedExponentData)
        guard let secKey = try? SecKey.representing(rsaPublicKeyComponents: components) else {
            XCTFail()
            return
        }

        let data = SecKeyCopyExternalRepresentation(secKey, nil)! as Data
        let dataExpected = SecKeyCopyExternalRepresentation(publicKeyAlice2048!, nil)! as Data

        XCTAssertEqual(data, dataExpected)
    }

    func testPublicKey4096FromPublicComponents() {
        let components = (expectedModulus4096Data, expectedExponentData)
        guard let secKey = try? SecKey.representing(rsaPublicKeyComponents: components) else {
            XCTFail()
            return
        }

        let data = SecKeyCopyExternalRepresentation(secKey, nil)! as Data
        let dataExpected = SecKeyCopyExternalRepresentation(publicKey4096!, nil)! as Data

        XCTAssertEqual(data, dataExpected)
    }

    func testPublicKeyFromMisformedModulus() {
        let components = ("ABCD".data(using: .utf8)!, "EFGH".data(using: .utf8)!)
        XCTAssertThrowsError(try SecKey.representing(rsaPublicKeyComponents: components))
    }

}
// swiftlint:enable force_unwrapping
