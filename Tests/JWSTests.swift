//
//  JWSTests.swift
//  Tests
//
//  Created by Carol Capek on 30.10.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import XCTest
@testable import SwiftJOSE

class JWSTests: XCTestCase {
    
    let message = "Hello world!"
    let privateKey = "privateKey"
    let publicKey = "publicKey"
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testSignAndSerialize() {
        let header = JWSHeader(algorithm: .rs512)
        let payload = JWSPayload(message.data(using: .utf8)!)
        let signer = RSASigner(key: privateKey)
        let jws = JWS(header: header, payload: payload, signer: signer)
        let compactSerializedJWS = jws.compactSerialized
        
        XCTAssertEqual(compactSerializedJWS, "eyJhbGciOiJSUzUxMiJ9.SGVsbG8gd29ybGQh.UlM1MTIoZXlKaGJHY2lPaUpTVXpVeE1pSjkuU0dWc2JHOGdkMjl5YkdRaCk")
        
        let secondJWS = JWS(compactSerialization: compactSerializedJWS)
        let verifier = RSAVerifier(key: publicKey)
        
        XCTAssertTrue(secondJWS.validates(against: verifier))
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
}
