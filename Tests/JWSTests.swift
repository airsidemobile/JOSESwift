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

    @available(*, deprecated)
    func testSignAndSerializeRS256() {
        self.performTestRSASign(algorithm: .RS256)
    }

    @available(*, deprecated)
    func testSignAndVerifyRS256WithNonRequiredHeaderParameter() {
        self.performTestRSASign(algorithm: .RS256, withKid: true)
    }

    func testDeserializeFromCompactSerializationRS256() {
        self.performTestRSADeserialization(algorithm: .RS256, compactSerializedJWS: compactSerializedJWSRS256Const)
    }


    @available(*, deprecated)
    func testSignAndSerializeRS512() {
        self.performTestRSASign(algorithm: .RS512)
    }

    @available(*, deprecated)
    func testSignAndVerifyRS512WithNonRequiredHeaderParameter() {
        self.performTestRSASign(algorithm: .RS512, withKid: true)
    }

    func testDeserializeFromCompactSerializationRS512() {
        self.performTestRSADeserialization(algorithm: .RS512, compactSerializedJWS: compactSerializedJWSRS512Const)
    }

    // MARK: - RSA Tests

    @available(*, deprecated)
    private func performTestRSASign(algorithm: SignatureAlgorithm, withKid: Bool? = false) {
        guard publicKeyAlice2048 != nil, privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        var header = JWSHeader(algorithm: algorithm)
        if withKid ?? false {
            header.kid = "kid"
        }

        let payload = Payload(message.data(using: .utf8)!)
        let signer = Signer(signingAlgorithm: algorithm, privateKey: privateKeyAlice2048!)!
        let jws = try! JWS(header: header, payload: payload, signer: signer)
        let compactSerializedJWS = jws.compactSerializedString

        XCTAssertEqual(compactSerializedJWS, compactSerializedJWS)

        let secondJWS = try! JWS(compactSerialization: compactSerializedJWS)

        XCTAssertTrue(secondJWS.isValid(for: publicKeyAlice2048!))
    }

    private func performTestRSADeserialization(algorithm: SignatureAlgorithm, compactSerializedJWS: String) {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let jws = try! JWS(compactSerialization: compactSerializedJWS)
        XCTAssertEqual(String(data: jws.header.data(), encoding: .utf8), "{\"alg\":\"\(algorithm.rawValue)\"}")
        XCTAssertEqual(String(data: jws.payload.data(), encoding: .utf8), "The true sign of intelligence is not knowledge but imagination.")

        let signer = Signer(signingAlgorithm: algorithm, privateKey: privateKeyAlice2048!)!
        let signature = try! signer.sign(header: JWSHeader(algorithm: algorithm), payload: Payload(message.data(using: .utf8)!))
        XCTAssertEqual(jws.signature.data(), signature)
    }
}
