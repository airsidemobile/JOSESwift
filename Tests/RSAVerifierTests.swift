//
//  RSAVerifierTests.swift
//  Tests
//
//  Created by Carol Capek on 03.11.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
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
        
        let jws = JWS(compactSerialization: compactSerializedJWSConst)
        let verifier = RSAVerifier(key: publicKey!)
        
        XCTAssertTrue(jws.validates(against: verifier))
    }
    
}
