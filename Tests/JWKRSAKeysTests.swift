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
        let builder = SecKeyJWKBuilder()
        let jwk = builder.set(publicKey: publicKey!).set("kty", to: "wrongKty").build()!

        XCTAssertNotEqual(jwk["kty"] as? String ?? "", "wrongKty")
    }

    func testMergingDuplicateAdditionalParametersInPrivateKey() {
        let builder = SecKeyJWKBuilder()
        let jwk = builder.set(privateKey: privateKey!).set("kty", to: "wrongKty").build()!

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
}
