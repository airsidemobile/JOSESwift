// swiftlint:disable force_unwrapping
//
//  JWSRSATests.swift
//  Tests
//
//  Created by Carol Capek on 30.10.17.
//  Renamed by Jarrod Moldrich on 28.10.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2024 Airside Mobile Inc.
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

class JWSRSATests: RSACryptoTestCase {

    func testSignAndSerializeRS256() {
        self.performTestRSASerializationValidationAndDeserialization(algorithm: .RS256)
    }

    func testSignAndVerifyRS256WithNonRequiredHeaderParameter() {
        self.performTestRSASerializationValidationAndDeserialization(algorithm: .RS256, withKid: true)
    }

    func testDeserializeFromCompactSerializationRS256() {
        self.performTestRSADeserialization(algorithm: .RS256, compactSerializedJWS: compactSerializedJWSRS256Const)
    }

    func testSignAndSerializeRS384() {
        self.performTestRSASerializationValidationAndDeserialization(algorithm: .RS384)
    }

    func testSignAndVerifyRS384WithNonRequiredHeaderParameter() {
        self.performTestRSASerializationValidationAndDeserialization(algorithm: .RS384, withKid: true)
    }

    func testDeserializeFromCompactSerializationRS384() {
        self.performTestRSADeserialization(algorithm: .RS384, compactSerializedJWS: compactSerializedJWSRS384Const)
    }

    func testSignAndSerializeRS512() {
        self.performTestRSASerializationValidationAndDeserialization(algorithm: .RS512)
    }

    func testSignAndVerifyRS512WithNonRequiredHeaderParameter() {
        self.performTestRSASerializationValidationAndDeserialization(algorithm: .RS512, withKid: true)
    }

    func testDeserializeFromCompactSerializationRS512() {
        self.performTestRSADeserialization(algorithm: .RS512, compactSerializedJWS: compactSerializedJWSRS512Const)
    }

    @available(iOS 11, *)
    func testSignVerifyAndDeserializeForPS256() {
        performTestRSASerializationValidationAndDeserialization(algorithm: .PS256)
    }

    @available(iOS 11, *)
    func testSignVerifyAndDeserializeForPS384() {
        performTestRSASerializationValidationAndDeserialization(algorithm: .PS384)
    }

    @available(iOS 11, *)
    func testSignVerifyAndDeserializeForPS512() {
        performTestRSASerializationValidationAndDeserialization(algorithm: .PS512)
    }

    // MARK: - RSA Tests

    private func performTestRSADeserialization(algorithm: SignatureAlgorithm, compactSerializedJWS: String) {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let jws = try! JWS(compactSerialization: compactSerializedJWS)
        XCTAssertEqual(String(data: jws.header.data(), encoding: .utf8), "{\"alg\":\"\(algorithm.rawValue)\"}")
        XCTAssertEqual(String(data: jws.payload.data(), encoding: .utf8), "The true sign of intelligence is not knowledge but imagination.")

        let signer = Signer(signatureAlgorithm: algorithm, key: privateKeyAlice2048!)!
        let signature = try! signer.sign(header: JWSHeader(algorithm: algorithm), payload: Payload(message.data(using: .utf8)!))
        XCTAssertEqual(jws.signature.data(), signature)
    }

    private func performTestRSASerializationValidationAndDeserialization(algorithm: SignatureAlgorithm, withKid: Bool = false) {
        guard publicKeyAlice2048 != nil, privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        var header = JWSHeader(algorithm: algorithm)
        if withKid {
            header.kid = "kid"
        }
        let payload = Payload(message.data(using: .utf8)!)
        let signer = Signer(signatureAlgorithm: algorithm, key: privateKeyAlice2048!)!
        let jws = try! JWS(header: header, payload: payload, signer: signer)
        let compactSerializedJWS = jws.compactSerializedString

        let secondJWS = try! JWS(compactSerialization: compactSerializedJWS)
        let verifier = Verifier(signatureAlgorithm: algorithm, key: publicKeyAlice2048!)

        XCTAssertTrue(secondJWS.isValid(for: verifier!))
        XCTAssertEqual(String(data: secondJWS.payload.data(), encoding: .utf8), "The true sign of intelligence is not knowledge but imagination.")

        guard withKid else {
            XCTAssertEqual(String(data: jws.header.data(), encoding: .utf8), "{\"alg\":\"\(algorithm.rawValue)\"}")
            return
        }

        let algKidHeader = "{\"alg\":\"\(algorithm.rawValue)\",\"kid\":\"kid\"}"
        let kidAlgHeader = "{\"kid\":\"kid\",\"alg\":\"\(algorithm.rawValue)\"}"

        let headerString = String(data: jws.header.data(), encoding: .utf8)

        guard headerString == algKidHeader || headerString == kidAlgHeader else {
            XCTFail("Incorrect header")
            return
        }
    }
}
// swiftlint:enable force_unwrapping
