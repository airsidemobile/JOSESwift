// swiftlint:disable force_unwrapping
//
//  JWSHMACTests.swift
//  Tests
//
//  Created by Tobias Hagemann on 15.04.21.
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

class JWSHMACTests: HMACCryptoTestCase {
    private func _testHMACDeserialization(algorithm: SignatureAlgorithm, compactSerializedJWS: String) {
        let jws = try! JWS(compactSerialization: compactSerializedJWS)
        XCTAssertEqual("{\"alg\":\"\(algorithm.rawValue)\"}", String(data: jws.header.data(), encoding: .utf8))
        XCTAssertEqual(message, String(data: jws.payload.data(), encoding: .utf8))

        let signer = Signer(signatureAlgorithm: algorithm, key: signingKey)!
        let signature = try! signer.sign(header: JWSHeader(algorithm: algorithm), payload: Payload(message.data(using: .utf8)!))
        XCTAssertEqual(jws.signature.data(), signature)
    }

    private func _testHMACSerializationValidationAndDeserialization(algorithm: SignatureAlgorithm) {
        let header = JWSHeader(algorithm: algorithm)
        let payload = Payload(message.data(using: .utf8)!)
        let signer = Signer(signatureAlgorithm: algorithm, key: signingKey)!
        let jws = try! JWS(header: header, payload: payload, signer: signer)
        let compactSerializedJWS = jws.compactSerializedString

        let secondJWS = try! JWS(compactSerialization: compactSerializedJWS)
        let verifier = Verifier(signatureAlgorithm: algorithm, key: signingKey)

        XCTAssertTrue(secondJWS.isValid(for: verifier!))
        XCTAssertEqual(message, String(data: secondJWS.payload.data(), encoding: .utf8))
        XCTAssertEqual("{\"alg\":\"\(algorithm.rawValue)\"}", String(data: jws.header.data(), encoding: .utf8))
    }

    func testHMACDeserialization() {
        _testHMACDeserialization(algorithm: .HS256, compactSerializedJWS: compactSerializedJWSHS256Const)
        _testHMACDeserialization(algorithm: .HS384, compactSerializedJWS: compactSerializedJWSHS384Const)
        _testHMACDeserialization(algorithm: .HS512, compactSerializedJWS: compactSerializedJWSHS512Const)
    }

    func testHMACSerializationValidationAndDeserialization() {
        _testHMACSerializationValidationAndDeserialization(algorithm: .HS256)
        _testHMACSerializationValidationAndDeserialization(algorithm: .HS384)
        _testHMACSerializationValidationAndDeserialization(algorithm: .HS512)
    }
}
// swiftlint:enable force_unwrapping
