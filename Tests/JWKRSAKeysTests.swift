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
        let key = RSAPublicKey(n: "n", e: "e")

        XCTAssertEqual(key.keyType, .RSA)
        XCTAssertEqual(key["kty"] as? String ?? "", "RSA")

        XCTAssertEqual(key.n, "n")
        XCTAssertEqual(key["n"] as? String ?? "", "n")

        XCTAssertEqual(key.e, "e")
        XCTAssertEqual(key["e"] as? String ?? "", "e")

        // kty, n, e
        XCTAssertEqual(key.parameters.count, 3)
    }

    func testInitPrivateKeyDirectlyWithoutAdditionalParameters() {
        let key = RSAPrivateKey(n: "n", e: "e", d: "d")

        XCTAssertEqual(key.keyType, .RSA)
        XCTAssertEqual(key["kty"] as? String ?? "", "RSA")

        XCTAssertEqual(key.n, "n")
        XCTAssertEqual(key["n"] as? String ?? "", "n")

        XCTAssertEqual(key.e, "e")
        XCTAssertEqual(key["e"] as? String ?? "", "e")

        XCTAssertEqual(key.d, "d")
        XCTAssertEqual(key["d"] as? String ?? "", "d")

        // kty, n, e, d
        XCTAssertEqual(key.parameters.count, 4)
    }
}
