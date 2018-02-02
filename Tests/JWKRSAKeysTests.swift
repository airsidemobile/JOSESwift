//
//  JWKRSAKeysTests.swift
//  Tests
//
//  Created by Daniel Egger on 21.12.17.
//

import XCTest
@testable import SwiftJOSE

class JWKRSAKeysTests: CryptoTestCase {

    func testMergingDuplicateAdditionalParametersInPublicKey() {
        let jwk = try! RSAPublicKey(publicKey: publicKey!, additionalParameters: [
            "kty": "wrongKty"
        ])

        XCTAssertNotEqual(jwk["kty"] as? String ?? "", "wrongKty")
    }

    func testMergingDuplicateAdditionalParametersInPrivateKey() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(privateKey: privateKey!).set("kty", to: "wrongKty").set(keyType: .RSA).build()!

        XCTAssertNotEqual(jwk["kty"] as? String ?? "", "wrongKty")
    }

    func testInitPublicKeyDirectlyWithoutAdditionalParameters() {
        let key = RSAPublicKey(modulus: "n", exponent: "e")

        XCTAssertEqual(key.keyType, .RSA)
        XCTAssertEqual(key["kty"] as? String ?? "", "RSA")

        XCTAssertEqual(key.modulus, "n")
        XCTAssertEqual(key["n"] as? String ?? "", "n")

        XCTAssertEqual(key.exponent, "e")
        XCTAssertEqual(key["e"] as? String ?? "", "e")

        // kty, n, e
        XCTAssertEqual(key.parameters.count, 3)
    }

    func testInitPrivateKeyDirectlyWithoutAdditionalParameters() {
        let key = RSAPrivateKey(modulus: "n", exponent: "e", privateExponent: "d")

        XCTAssertEqual(key.keyType, .RSA)
        XCTAssertEqual(key["kty"] as? String ?? "", "RSA")

        XCTAssertEqual(key.modulus, "n")
        XCTAssertEqual(key["n"] as? String ?? "", "n")

        XCTAssertEqual(key.exponent, "e")
        XCTAssertEqual(key["e"] as? String ?? "", "e")

        XCTAssertEqual(key.privateExponent, "d")
        XCTAssertEqual(key["d"] as? String ?? "", "d")

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
