//
//  JWKParameterTests.swift
//  Tests
//
//  Created by Daniel Egger on 21.12.17.
//

import XCTest
@testable import SwiftJOSE

class JWKParameterTests: CryptoTestCase {

    func testPrivateKeyKeyTypeIsPresent() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(privateKey: privateKey!).set(keyType: .RSA).build()!

        XCTAssertEqual(jwk.keyType, .RSA)
        XCTAssertEqual(jwk[JWKParameter.keyType.rawValue] as? String ?? "", JWKKeyType.RSA.rawValue)
        XCTAssertEqual(jwk.parameters[JWKParameter.keyType.rawValue] as? String ?? "", JWKKeyType.RSA.rawValue)
    }

    func testPublicKeyKeyTypeIsPresent() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(publicKey: publicKey!).set(keyType: .RSA).build()!

        XCTAssertEqual(jwk.keyType, .RSA)
        XCTAssertEqual(jwk[JWKParameter.keyType.rawValue] as? String ?? "", JWKKeyType.RSA.rawValue)
        XCTAssertEqual(jwk.parameters[JWKParameter.keyType.rawValue] as? String ?? "", JWKKeyType.RSA.rawValue)
    }

    func testSettingAndGettingAdditionalParameter() {
        let builder = JWKBuilder<SecKey>()
        let jwk = builder.set(publicKey: publicKey!).set("kid", to: "new on the block").set(keyType: .RSA).build()!

        XCTAssertEqual(jwk["kid"] as? String ?? "", "new on the block")
    }

}
