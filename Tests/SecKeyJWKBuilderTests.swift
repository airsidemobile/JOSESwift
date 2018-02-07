//
//  SecKeyJWKBuilderTests.swift
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

class SecKeyJWKBuilderTests: CryptoTestCase {

    func testBuildingPublicKey() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(publicKey: publicKey!).set(keyType: .RSA).build()

        XCTAssertNotNil(jwk)

        XCTAssertTrue(jwk is RSAPublicKey)
        XCTAssertFalse(jwk is RSAPrivateKey)
        XCTAssertFalse(jwk is RSAKeyPair)
    }

    func testBuildingPrivateKey() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(privateKey: privateKey!).set(keyType: .RSA).build()

        XCTAssertNotNil(jwk)

        XCTAssertFalse(jwk is RSAPublicKey)
        XCTAssertTrue(jwk is RSAPrivateKey)
        XCTAssertTrue(jwk is RSAKeyPair)
    }

    func testBuildingKeyPair() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(privateKey: privateKey!).set(publicKey: publicKey!).set(keyType: .RSA).build()

        XCTAssertNotNil(jwk)

        XCTAssertFalse(jwk is RSAPublicKey)
        XCTAssertTrue(jwk is RSAPrivateKey)
        XCTAssertTrue(jwk is RSAKeyPair)
    }

    func testBuildingWithoutSettingKeys() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(keyType: .RSA).build()

        XCTAssertNil(jwk)
    }

    func testBuildingWithoutSettingKeyType() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(privateKey: privateKey!).set(publicKey: publicKey!).build()

        XCTAssertNil(jwk)
    }

    func testBuildingWithoutAnything() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.build()

        XCTAssertNil(jwk)
    }

}
