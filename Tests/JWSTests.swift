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

class JWSTests: CryptoTestCase {
    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testSignAndSerialize() {
        guard publicKeyAlice2048 != nil, privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let header = JWSHeader(algorithm: .RS512)
        let payload = Payload(message.data(using: .utf8)!)
        let signer = Signer(signingAlgorithm: .RS512, privateKey: privateKeyAlice2048!)!
        let jws = try! JWS(header: header, payload: payload, signer: signer)
        let compactSerializedJWS = jws.compactSerializedString

        XCTAssertEqual(compactSerializedJWS, compactSerializedJWSConst)

        let secondJWS = try! JWS(compactSerialization: compactSerializedJWS)

        XCTAssertTrue(secondJWS.isValid(for: publicKeyAlice2048!))
    }

    func testDeserializeFromCompactSerialization() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let jws = try! JWS(compactSerialization: compactSerializedJWSConst)
        XCTAssertEqual(String(data: jws.header.data(), encoding: .utf8), "{\"alg\":\"RS512\"}")
        XCTAssertEqual(String(data: jws.payload.data(), encoding: .utf8), "The true sign of intelligence is not knowledge but imagination.")

        let signer = Signer(signingAlgorithm: .RS512, privateKey: privateKeyAlice2048!)!
        let signature = try! signer.sign(header: JWSHeader(algorithm: .RS512), payload: Payload(message.data(using: .utf8)!))
        XCTAssertEqual(jws.signature.data(), signature)
    }
}
