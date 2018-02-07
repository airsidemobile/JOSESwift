//
//  JWKRSAKeysTests.swift
//  Tests
//
//  Created by Daniel Egger on 21.12.17.
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

class JWKRSAKeysTests: CryptoTestCase {

    func testMergingDuplicateAdditionalParametersInPublicKey() {
        let jwk = try! RSAPublicKey(publicKey: publicKey!, additionalParameters: [
            "kty": "wrongKty"
        ])

        XCTAssertNotEqual(jwk["kty"] ?? "", "wrongKty")
    }

    func testMergingDuplicateAdditionalParametersInPrivateKey() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(privateKey: privateKey!).set("kty", to: "wrongKty").set(keyType: .RSA).build()!

        XCTAssertNotEqual(jwk["kty"] ?? "", "wrongKty")
    }

    func testInitPublicKeyDirectlyWithoutAdditionalParameters() {
        let key = RSAPublicKey(modulus: "n", exponent: "e")

        XCTAssertEqual(key.keyType, .RSA)
        XCTAssertEqual(key["kty"] ?? "", "RSA")

        XCTAssertEqual(key.modulus, "n")
        XCTAssertEqual(key["n"] ?? "", "n")

        XCTAssertEqual(key.exponent, "e")
        XCTAssertEqual(key["e"] ?? "", "e")

        // kty, n, e
        XCTAssertEqual(key.parameters.count, 3)
    }

    func testInitPrivateKeyDirectlyWithoutAdditionalParameters() {
        let key = RSAPrivateKey(modulus: "n", exponent: "e", privateExponent: "d")

        XCTAssertEqual(key.keyType, .RSA)
        XCTAssertEqual(key["kty"] ?? "", "RSA")

        XCTAssertEqual(key.modulus, "n")
        XCTAssertEqual(key["n"] ?? "", "n")

        XCTAssertEqual(key.exponent, "e")
        XCTAssertEqual(key["e"] ?? "", "e")

        XCTAssertEqual(key.privateExponent, "d")
        XCTAssertEqual(key["d"] ?? "", "d")

        // kty, n, e, d
        XCTAssertEqual(key.parameters.count, 4)
    }

    func testBuiltPrivateKeyParametersArePresent() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(privateKey: privateKey!).set(keyType: .RSA).build() as! RSAPrivateKey

        XCTAssertFalse(jwk.modulus.isEmpty)
        XCTAssertFalse(jwk.exponent.isEmpty)
        XCTAssertFalse(jwk.privateExponent.isEmpty)
    }

    func testBuiltPublicKeyParametersArePresent() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(publicKey: publicKey!).set(keyType: .RSA).build() as! RSAPublicKey

        XCTAssertFalse(jwk.modulus.isEmpty)
        XCTAssertFalse(jwk.exponent.isEmpty)
    }
}
