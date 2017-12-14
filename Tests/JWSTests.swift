//
//  JWSTests.swift
//  Tests
//
//  Created by Carol Capek on 30.10.17.
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
        let payload = Payload(message.data(using: .utf8)!)
        let signer = Signer(signingAlgorithm: .RS512, privateKey: privateKey!)
        let jws = JWS(header: header, payload: payload, signer: signer)!
        let compactSerializedJWS = jws.compactSerialized

        XCTAssertEqual(compactSerializedJWS, compactSerializedJWSConst)

        let secondJWS = try! JWS(compactSerialization: compactSerializedJWS)

        XCTAssertTrue(secondJWS.isValid(for: publicKey!))
    }

    func testDeserializeFromCompactSerialization() {
        guard privateKey != nil else {
            XCTFail()
            return
        }

        let jws = try! JWS(compactSerialization: compactSerializedJWSConst)
        XCTAssertEqual(String(data: jws.header.data(), encoding: .utf8), "{\"alg\":\"RS512\"}")
        XCTAssertEqual(String(data: jws.payload.data(), encoding: .utf8), "The true sign of intelligence is not knowledge but imagination.")

        let signer = Signer(signingAlgorithm: .RS512, privateKey: privateKey!)
        let signature = try! signer.sign(header: JWSHeader(algorithm: .RS512), payload: Payload(message.data(using: .utf8)!))
        XCTAssertEqual(jws.signature.data(), signature)
    }
}
