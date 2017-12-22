//
//  JWKParameterTests.swift
//  Tests
//
//  Created by Daniel Egger on 21.12.17.
//

import XCTest
@testable import SwiftJOSE

class JWKParameterTests: CryptoTestCase {

    func testPrivateKeyBuilding() {
        let builder = SecKeyJWKBuilder()
        let jwk = builder.set(privateKey: privateKey!).build()

        XCTAssertNotNil(jwk)
        XCTAssertTrue(jwk is PrivateKey)
        XCTAssertTrue(jwk is RSAPrivateKey)
        XCTAssertTrue(jwk is RSAKeyPair)
        XCTAssertFalse(jwk is RSAPublicKey)
    }

    func testPrivateKeyKeyTypeIsPresent() {
        let builder = SecKeyJWKBuilder()
        let jwk = builder.set(privateKey: privateKey!).build() as! RSAPrivateKey

        XCTAssertEqual(jwk.keyType, .RSA)
        XCTAssertEqual(jwk[JWKKeyType.RSA.parameterName] as? String ?? "", JWKKeyType.RSA.rawValue)
        XCTAssertEqual(jwk.parameters[JWKKeyType.RSA.parameterName] as? String ?? "", JWKKeyType.RSA.rawValue)
    }

    func testPrivateKeyParametersArePresent() {
        let builder = SecKeyJWKBuilder()
        let jwk = builder.set(privateKey: privateKey!).build() as! RSAPrivateKey

        XCTAssertFalse(jwk.modulus.isEmpty)
        XCTAssertFalse(jwk.exponent.isEmpty)
        XCTAssertFalse(jwk.privateExponent.isEmpty)
    }

    func testPublicKeyParametersArePresent() {
        let builder = SecKeyJWKBuilder()
        let jwk = builder.set(publicKey: publicKey!).build() as! RSAPublicKey

        XCTAssertFalse(jwk.modulus.isEmpty)
        XCTAssertFalse(jwk.exponent.isEmpty)
    }

    func testSettingAndGettingAdditionalParameter() {
        let builder = SecKeyJWKBuilder()
        let jwk = builder.set(publicKey: publicKey!).set("kid", to: "new on the block").build()!

        XCTAssertEqual(jwk["kid"] as? String ?? "", "new on the block")
    }
    
}
