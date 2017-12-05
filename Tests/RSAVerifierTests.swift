//
//  RSAVerifierTests.swift
//  Tests
//
//  Created by Carol Capek on 03.11.17.
//

import XCTest
@testable import SwiftJOSE

class RSAVerifierTests: CryptoTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testVerifying() {
        guard publicKey != nil else {
            XCTFail()
            return
        }

        let jws = try! JWS(compactSerialization: compactSerializedJWSConst)
        let verifier = RSAVerifier(key: publicKey!)

        XCTAssertTrue(jws.validates(against: verifier))
    }

}
