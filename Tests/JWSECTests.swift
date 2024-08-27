// swiftlint:disable force_unwrapping
//
//  JWSECTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 28.10.18.
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

class JWSECTests: ECCryptoTestCase {

    func testSignAndSerialize() {
        allTestData.forEach { testData in
            self.performTestECSign(testData: testData)
        }
    }

    func testDeserializeFromCompactSerialization() {
        allTestData.forEach { testData in
            self.performTestECDeserialization(testData: testData)
        }
    }

    // MARK: - EC Tests

    private func performTestECSign(testData: ECTestKeyData) {
        let algorithm = SignatureAlgorithm(rawValue: testData.signatureAlgorithm)!
        let header = JWSHeader(algorithm: algorithm)
        let payload = Payload(plainTextPayload.data(using: .utf8)!)
        let signer = Signer(signatureAlgorithm: algorithm, key: testData.privateKey)!
        let verifier = Verifier(signatureAlgorithm: algorithm, key: testData.publicKey)!
        let jws = try! JWS(header: header, payload: payload, signer: signer)
        let compact = jws.compactSerializedString
        let splitCompact = compact.split(separator: ".")

        XCTAssertEqual(String(splitCompact[0]), testData.compactSerializedJWSSimpleHeaderConst)
        XCTAssertEqual(String(splitCompact[1]), testData.compactSerializedJWSPayloadConst)
        // n.b.: we can't verify the signature with a constant as ECDSA internally uses a nonce
        XCTAssertNotEqual(String(splitCompact[2]), testData.compactSerializedJWSSignatureConst)

        let secondJWS = try! JWS(compactSerialization: compact)

        XCTAssertTrue(secondJWS.isValid(for: verifier))
    }

    private func performTestECDeserialization(testData: ECTestKeyData) {
        let jws = try! JWS(compactSerialization: testData.compactSerializedJWSConst)
        let header = String(data: jws.header.data(), encoding: .utf8)
        let payload = String(data: jws.payload.data(), encoding: .utf8)
        XCTAssertEqual(header, getHeader(with: testData.signatureAlgorithm))
        XCTAssertEqual(payload, plainTextPayload)
    }
}
// swiftlint:enable force_unwrapping
