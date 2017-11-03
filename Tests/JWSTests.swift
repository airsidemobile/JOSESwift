//
//  JWSTests.swift
//  Tests
//
//  Created by Carol Capek on 30.10.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import XCTest
@testable import SwiftJOSE

class JWSTests: CryptoTestCase {
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testSignAndSerialize() {
        let header = JWSHeader(algorithm: .RS512)
        let payload = JWSPayload(message.data(using: .utf8)!)
        let signer = RSASigner(key: privateKey)
        let jws = JWS(header: header, payload: payload, signer: signer)
        let compactSerializedJWS = jws.compactSerialized
        
        XCTAssertEqual(compactSerializedJWS, "eyJhbGciOiJSUzUxMiJ9.SGVsbG8gd29ybGQh.UlM1MTIoZXlKaGJHY2lPaUpTVXpVeE1pSjkuU0dWc2JHOGdkMjl5YkdRaCk")
        
        let secondJWS = JWS(compactSerialization: compactSerializedJWS)
        let verifier = RSAVerifier(key: publicKey)
        
        XCTAssertTrue(secondJWS.validates(against: verifier))
    }
    
    func testDeserializeFromCompactSerialization() {
        let compactSerializedJWS = "eyJhbGciOiJSUzUxMiJ9.SGVsbG8gd29ybGQh.UlM1MTIoZXlKaGJHY2lPaUpTVXpVeE1pSjkuU0dWc2JHOGdkMjl5YkdRaCk"
        
        let jws = JWS(compactSerialization: compactSerializedJWS)
        XCTAssertEqual(jws.description, "[\"alg\": RS512] . Hello world! . RS512(eyJhbGciOiJSUzUxMiJ9.SGVsbG8gd29ybGQh)")
    }
}
