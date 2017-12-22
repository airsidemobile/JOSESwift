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
        let jwk = SecKeyJWKBuilder()
            .set(publicKey: publicKey!)
            .set("alg", to: "RS256")
            .set("kid", to: "2011-04-29")
            .build()!

        let jsonString = try? jwk.jsonString()
        XCTAssertNotNil(jsonString)

        let jsonData = jsonString!.data(using: .utf8)!
        let dict = try? JSONSerialization.jsonObject(with: jsonData, options: []) as! [String: Any]
        XCTAssertNotNil(dict!)

        XCTAssertEqual(dict!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(dict!["kid"] as? String ?? "", "2011-04-29")
        XCTAssertEqual(dict!["alg"] as? String ?? "", "RS256")

        // Todo: Update with real values. See https://mohemian.atlassian.net/browse/JOSE-93.
        XCTAssertEqual(dict!["n"] as? String ?? "", "0vx...Kgw")
        XCTAssertEqual(dict!["e"] as? String ?? "", "AQAB")
    }

    func testJSONData() {
        let jwk = SecKeyJWKBuilder()
            .set(publicKey: publicKey!)
            .set("alg", to: "RS256")
            .set("kid", to: "2011-04-29")
            .build()!

        let jsonData = try? jwk.jsonData()
        XCTAssertNotNil(jsonData!)

        let dict = try? JSONSerialization.jsonObject(with: jsonData!, options: []) as! [String: Any]
        XCTAssertNotNil(dict!)

        XCTAssertEqual(dict!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(dict!["kid"] as? String ?? "", "2011-04-29")
        XCTAssertEqual(dict!["alg"] as? String ?? "", "RS256")

        // Todo: Update with real values. See https://mohemian.atlassian.net/browse/JOSE-93.
        XCTAssertEqual(dict!["n"] as? String ?? "", "0vx...Kgw")
        XCTAssertEqual(dict!["e"] as? String ?? "", "AQAB")
    }

    func testJSONStringWithInvalidParameters() {
        let jwk = SecKeyJWKBuilder()
            .set(publicKey: publicKey!)
            .set("notJSONConvertible", to: Date())
            .build()!

        XCTAssertThrowsError(try jwk.jsonString())
    }

    func testJSONDataWithInvalidParameters() {
        let jwk = SecKeyJWKBuilder()
            .set(publicKey: publicKey!)
            .set("notJSONConvertible", to: Date())
            .build()!

        XCTAssertThrowsError(try jwk.jsonData())
    }

}
