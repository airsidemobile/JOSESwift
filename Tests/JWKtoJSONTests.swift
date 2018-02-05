//
//  JWKtoJSONTests.swift
//  Tests
//
//  Created by Daniel Egger on 21.12.17.
//

import XCTest
@testable import SwiftJOSE

class JWKtoJSONTests: CryptoTestCase {

    func testJSONString() {
        let jwk = JWKBuilder<SecKey>()
            .set(publicKey: publicKey!)
            .set("alg", to: "RS256")
            .set("kid", to: "2011-04-29")
            .set(keyType: .RSA)
            .build()!

        let jsonString = try? jwk.jsonString()
        XCTAssertNotNil(jsonString)

        let jsonData = jsonString!.data(using: .utf8)!
        let dict = try? JSONSerialization.jsonObject(with: jsonData, options: []) as! [String: Any]
        XCTAssertNotNil(dict!)

        XCTAssertEqual(dict!["kty"] as? String ?? "", "RSA")
        XCTAssertEqual(dict!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(dict!["kid"] as? String ?? "", "2011-04-29")

        // Todo: Update with real values. See https://mohemian.atlassian.net/browse/JOSE-93.
        XCTAssertEqual(dict!["n"] as? String ?? "", "MHZ4Li4uS2d3")
        XCTAssertEqual(dict!["e"] as? String ?? "", "QVFBQg")
    }

    func testJSONData() {
        let jwk = JWKBuilder<SecKey>()
            .set(publicKey: publicKey!)
            .set("alg", to: "RS256")
            .set("kid", to: "2011-04-29")
            .set(keyType: .RSA)
            .build()!

        let jsonData = try? jwk.jsonData()
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
}
