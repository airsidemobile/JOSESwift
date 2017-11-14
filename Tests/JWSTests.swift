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
        guard publicKey != nil, privateKey != nil else {
            XCTFail()
            return
        }
        
        let header = JWSHeader(algorithm: .RS512)
        let payload = JWSPayload(message.data(using: .utf8)!)
        let signer = RSASigner(key: privateKey!)
        let jws = JWS(header: header, payload: payload, signer: signer)
        let compactSerializedJWS = jws.compactSerialized

        XCTAssertEqual(compactSerializedJWS, compactSerializedJWSConst)
        
        let secondJWS = JWS(compactSerialization: compactSerializedJWS)
        let verifier = RSAVerifier(key: publicKey!)
        
        XCTAssertTrue(secondJWS.validates(against: verifier))
    }
    
    func testDeserializeFromCompactSerialization() {
        guard privateKey != nil else {
            XCTFail()
            return
        }
        
        let jws = JWS(compactSerialization: compactSerializedJWSConst)
        XCTAssertEqual(String(data: jws.header.data(), encoding: .utf8), "{\"alg\":\"RS512\"}")
        XCTAssertEqual(String(data: jws.payload.data(), encoding: .utf8), "The true sign of intelligence is not knowledge but imagination.")
        
        let signer = RSASigner(key: privateKey!)
        let signature = Signature(from: signer, using: JWSHeader(algorithm: .RS512), and: JWSPayload(message.data(using: .utf8)!))
        XCTAssertEqual(jws.signature.data(), signature?.data())
    }
}
