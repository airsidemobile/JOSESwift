// swiftlint:disable force_unwrapping
//
//  JWKRSAKeysTests.swift
//  Tests
//
//  Created by Daniel Egger on 21.12.17.
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

class JWKRSAKeysTests: RSACryptoTestCase {

    func testMergingDuplicateAdditionalParametersInPublicKey() {
        let jwk = try! RSAPublicKey(publicKey: publicKeyAlice2048!, additionalParameters: [
            "kty": "wrongKty"
        ])

        XCTAssertEqual(jwk["kty"] ?? "", "RSA")
    }

    func testMergingDuplicateAdditionalParametersInPrivateKey() {
        let jwk = RSAPrivateKey(
            modulus: "MHZ4Li4uS2d3",
            exponent: "QVFBQg",
            privateExponent: "MHZ4Li4uS2d3",
            additionalParameters: [ "kty": "wrongKty" ]
        )

        XCTAssertEqual(jwk["kty"] ?? "", "RSA")
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

    func testPublicKeyKeyTypeIsPresent() {
        let jwk = try! RSAPublicKey(publicKey: publicKeyAlice2048!)

        XCTAssertEqual(jwk.keyType, .RSA)
        XCTAssertEqual(jwk[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.RSA.rawValue)
        XCTAssertEqual(jwk.parameters[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.RSA.rawValue)
    }

    func testPrivateKeyKeyTypeIsPresent() {
        let jwk = RSAPrivateKey(modulus: "A", exponent: "B", privateExponent: "C")

        XCTAssertEqual(jwk.keyType, .RSA)
        XCTAssertEqual(jwk[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.RSA.rawValue)
        XCTAssertEqual(jwk.parameters[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.RSA.rawValue)
    }

    func testSettingAndGettingAdditionalParameter() {
        let jwk = try! RSAPublicKey(publicKey: publicKeyAlice2048!, additionalParameters: [
            "kid": "new on the block"
            ])

        XCTAssertEqual(jwk["kid"] ?? "", "new on the block")
    }

    func testPublicKeyAllParametersArePresentInDict() {
        let jwk = try! RSAPublicKey(publicKey: publicKeyAlice2048!, additionalParameters: [
            "kid": "new on the block",
            "use": "test"
        ])

        XCTAssertEqual(jwk.parameters.count, 5)
    }

    func testPrivateKeyAllParametersArePresentInDict() {
        let jwk = RSAPrivateKey(modulus: "A", exponent: "B", privateExponent: "C", additionalParameters: [
            "kid": "new on the block",
            "use": "test"
            ])

        XCTAssertEqual(jwk.parameters.count, 6)
    }

    @available(iOS 11.0, *)
    func testThumbprintPublicKey() {
        let jwk = RSAPublicKey(modulus: "n", exponent: "e")
        XCTAssertEqual(try? jwk.thumbprint(), "lPd1Hx7fpYY23pQVKnFvOEtk_jFe5EV8ZISUGTSGA_U")
    }

    @available(iOS 11.0, *)
    func testThumbprintPrivateKey() {
        let jwk = RSAPrivateKey(modulus: "A", exponent: "B", privateExponent: "C")
        XCTAssertEqual(try? jwk.thumbprint(), "slXDutAKWp8bubkrYoqeq5EwSQDtZdooHiG4TVQUptY")
    }

    @available(iOS 11.0, *)
    func testAddPublicThumbprintToJWK() throws {
        let jwk = try RSAPublicKey(modulus: "n", exponent: "e").withThumbprintAsKeyId()
        XCTAssertEqual(jwk.parameters[JWKParameter.keyIdentifier.rawValue], "lPd1Hx7fpYY23pQVKnFvOEtk_jFe5EV8ZISUGTSGA_U")
    }

    @available(iOS 11.0, *)
    func testAddPublicThumbprintToJWKCopyParamters() throws {
        let useKey = "sig"
        let jwk = try RSAPublicKey(modulus: "n", exponent: "e", additionalParameters: [JWKParameter.keyUse.rawValue: useKey]).withThumbprintAsKeyId()
        XCTAssertEqual(jwk.parameters[JWKParameter.keyIdentifier.rawValue], "lPd1Hx7fpYY23pQVKnFvOEtk_jFe5EV8ZISUGTSGA_U")
        XCTAssertEqual(jwk.parameters[JWKParameter.keyUse.rawValue], useKey)
    }

    @available(iOS 11.0, *)
    func testAddPrivateThumbprintToJWK() throws {
        let jwk = try RSAPrivateKey(modulus: "A", exponent: "B", privateExponent: "C").withThumbprintAsKeyId()
        XCTAssertEqual(jwk.parameters[JWKParameter.keyIdentifier.rawValue], "slXDutAKWp8bubkrYoqeq5EwSQDtZdooHiG4TVQUptY")
    }

    @available(iOS 11.0, *)
    func testAddPrivateThumbprintToJWKCopyParamters() throws {
        let useKey = "sig"
        let jwk = try RSAPrivateKey(modulus: "A", exponent: "B", privateExponent: "C", additionalParameters: [JWKParameter.keyUse.rawValue: useKey]).withThumbprintAsKeyId()
        XCTAssertEqual(jwk.parameters[JWKParameter.keyIdentifier.rawValue], "slXDutAKWp8bubkrYoqeq5EwSQDtZdooHiG4TVQUptY")
        XCTAssertEqual(jwk.parameters[JWKParameter.keyUse.rawValue], useKey)
    }
}
// swiftlint:enable force_unwrapping
