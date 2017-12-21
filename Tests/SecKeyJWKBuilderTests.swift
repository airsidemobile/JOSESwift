//
//  SecKeyJWKBuilderTests.swift
//  Tests
//
//  Created by Daniel Egger on 21.12.17.
//

import XCTest
@testable import SwiftJOSE

class SecKeyJWKBuilderTests: CryptoTestCase {
    
    func testBuildingPublicKey() {
        let builder = SecKeyJWKBuilder()
        let jwk = builder.set(publicKey: publicKey!).build()

        XCTAssertNotNil(jwk)

        XCTAssertTrue(jwk is PublicKey)
        XCTAssertFalse(jwk is PrivateKey)
        XCTAssertFalse(jwk is KeyPair)

        XCTAssertTrue(jwk is RSAPublicKey)
        XCTAssertFalse(jwk is RSAPrivateKey)
        XCTAssertFalse(jwk is RSAKeyPair)
    }

    func testBuilingPrivateKey() {
        let builder = SecKeyJWKBuilder()
        let jwk = builder.set(privateKey: privateKey!).build()

        XCTAssertNotNil(jwk)

        XCTAssertFalse(jwk is PublicKey)
        XCTAssertTrue(jwk is PrivateKey)
        XCTAssertTrue(jwk is KeyPair)

        XCTAssertFalse(jwk is RSAPublicKey)
        XCTAssertTrue(jwk is RSAPrivateKey)
        XCTAssertTrue(jwk is RSAKeyPair)
    }

    func testBuildingKeyPair() {
        let builder = SecKeyJWKBuilder()
        let jwk = builder.set(privateKey: privateKey!).set(publicKey: publicKey!).build()

        XCTAssertNotNil(jwk)

        XCTAssertFalse(jwk is PublicKey)
        XCTAssertTrue(jwk is PrivateKey)
        XCTAssertTrue(jwk is KeyPair)

        XCTAssertFalse(jwk is RSAPublicKey)
        XCTAssertTrue(jwk is RSAPrivateKey)
        XCTAssertTrue(jwk is RSAKeyPair)
    }

    func testBuilingWithoutSettingAKey() {
        let builder = SecKeyJWKBuilder()
        let jwk = builder.build()

        XCTAssertNil(jwk)
    }
    
}
