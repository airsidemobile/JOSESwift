//
//  JWKParameterTests.swift
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

class JWKParameterTests: CryptoTestCase {

    func testPrivateKeyKeyTypeIsPresent() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(privateKey: privateKey!).set(keyType: .RSA).build()!

        XCTAssertEqual(jwk.keyType, .RSA)
        XCTAssertEqual(jwk[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.RSA.rawValue)
        XCTAssertEqual(jwk.parameters[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.RSA.rawValue)
    }

    func testPublicKeyKeyTypeIsPresent() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(publicKey: publicKey!).set(keyType: .RSA).build()!

        XCTAssertEqual(jwk.keyType, .RSA)
        XCTAssertEqual(jwk[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.RSA.rawValue)
        XCTAssertEqual(jwk.parameters[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.RSA.rawValue)
    }

    func testSettingAndGettingAdditionalParameter() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(publicKey: publicKey!).set("kid", to: "new on the block").set(keyType: .RSA).build()!

        XCTAssertEqual(jwk["kid"] ?? "", "new on the block")
    }

}
