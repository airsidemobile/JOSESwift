//
//  JWSTests.swift
//  Tests
//
//  Created by Carol Capek on 30.10.17.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import XCTest
@testable import JOSESwift

class JWSTests: RSACryptoTestCase {
    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testSignAndSerializeRS256() {
        self.performTestRSASign(algorithm: .RS256, compactSerializedJWS: compactSerializedJWSRS256Const)
    }

    func testDeserializeFromCompactSerializationRS256() {
        self.performTestRSADeserialization(algorithm: .RS256, compactSerializedJWS: compactSerializedJWSRS256Const)
    }

    func testSignAndSerializeRS512() {
        self.performTestRSASign(algorithm: .RS512, compactSerializedJWS: compactSerializedJWSRS512Const)
    }

    func testDeserializeFromCompactSerializationRS512() {
        self.performTestRSADeserialization(algorithm: .RS512, compactSerializedJWS: compactSerializedJWSRS512Const)
    }

    // MARK: - RSA Tests

    private func performTestRSASign(algorithm: SignatureAlgorithm, compactSerializedJWS: String) {
        guard publicKey2048 != nil, privateKey2048 != nil else {
            XCTFail()
            return
        }

        let header = JWSHeader(algorithm: algorithm)
        let payload = Payload(message.data(using: .utf8)!)
        let signer = Signer(signingAlgorithm: algorithm, privateKey: privateKey2048!)!
        let jws = try! JWS(header: header, payload: payload, signer: signer)
        let compactSerializedJWS = jws.compactSerializedString

        XCTAssertEqual(compactSerializedJWS, compactSerializedJWS)

        let secondJWS = try! JWS(compactSerialization: compactSerializedJWS)

        XCTAssertTrue(secondJWS.isValid(for: publicKey2048!))
    }

    private func performTestRSADeserialization(algorithm: SignatureAlgorithm, compactSerializedJWS: String) {
        guard privateKey2048 != nil else {
            XCTFail()
            return
        }

        let jws = try! JWS(compactSerialization: compactSerializedJWS)
        XCTAssertEqual(String(data: jws.header.data(), encoding: .utf8), "{\"alg\":\"\(algorithm.rawValue)\"}")
        XCTAssertEqual(String(data: jws.payload.data(), encoding: .utf8), "The true sign of intelligence is not knowledge but imagination.")

        let signer = Signer(signingAlgorithm: algorithm, privateKey: privateKey2048!)!
        let signature = try! signer.sign(header: JWSHeader(algorithm: algorithm), payload: Payload(message.data(using: .utf8)!))
        XCTAssertEqual(jws.signature.data(), signature)
    }
}
