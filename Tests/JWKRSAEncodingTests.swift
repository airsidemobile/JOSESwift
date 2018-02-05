//
//  JWKRSAEncodingTests.swift
//  Tests
//
//  Created by Daniel Egger on 05.02.18.
//

import XCTest
@testable import SwiftJOSE

class JWKRSAEncodingTests: CryptoTestCase {

    func testEncoding() {
        let jwk = JWKBuilder<SecKey>()
            .set(publicKey: publicKey!)
            .set("alg", to: "RS256")
            .set("kid", to: "2011-04-29")
            .set(keyType: .RSA)
            .build()! as! RSAPublicKey

        let jsonData = try? JSONEncoder().encode(jwk)
        XCTAssertNotNil(jsonData!)

        let dict = try? JSONSerialization.jsonObject(with: jsonData!, options: []) as! [String: Any]
        XCTAssertNotNil(dict!)

        XCTAssertEqual(dict!["kty"] as? String ?? "", "RSA")
        XCTAssertEqual(dict!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(dict!["kid"] as? String ?? "", "2011-04-29")

        // Todo: Update with real values. See https://mohemian.atlassian.net/browse/JOSE-93.
        XCTAssertEqual(dict!["n"] as? String ?? "", "MHZ4Li4uS2d3")
        XCTAssertEqual(dict!["e"] as? String ?? "", "QVFBQg")
    }

    func testEncodingWithUnregisteredParameter() {
        let jwk = JWKBuilder<SecKey>()
            .set(publicKey: publicKey!)
            .set("alg", to: "RS256")
            .set("kid", to: "2011-04-29")
            .set("breeze", to: "through")
            .set(keyType: .RSA)
            .build()! as! RSAPublicKey

        let jsonData = try? JSONEncoder().encode(jwk)
        XCTAssertNotNil(jsonData!)

        let dict = try? JSONSerialization.jsonObject(with: jsonData!, options: []) as! [String: Any]
        XCTAssertNotNil(dict!)

        XCTAssertEqual(dict!["kty"] as? String ?? "", "RSA")
        XCTAssertEqual(dict!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(dict!["kid"] as? String ?? "", "2011-04-29")
        XCTAssertNil(dict!["breeze"])

        // Todo: Update with real values. See https://mohemian.atlassian.net/browse/JOSE-93.
        XCTAssertEqual(dict!["n"] as? String ?? "", "MHZ4Li4uS2d3")
        XCTAssertEqual(dict!["e"] as? String ?? "", "QVFBQg")
    }

}
