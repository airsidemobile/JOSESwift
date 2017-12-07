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
        let verifier = RSAVerifier(algorithm: .RS512, publicKey: publicKey!)
        
        let encoded = [jws.header, jws.payload].map { (component: DataConvertible) in
            return component.data().base64URLEncodedString()
        }
        
        guard let signingInput = encoded.joined(separator: ".").data(using: .ascii) else {
            XCTFail()
            return
        }

        XCTAssertTrue(try! verifier.verify(signingInput, against: jws.signature))
    }

}
