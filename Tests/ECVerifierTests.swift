//
//  ECVerifierTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 08.10.17.
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

class ECVerifierTests: ECCryptoTestCase {

    private func _testVerifying(algorithm: SignatureAlgorithm, keyData: ECTestKeyData, validSignature: Bool = true) -> Bool {
        let validJWS = keyData.compactSerializedJWSConst
        let serializedJWS = validSignature ? validJWS : invalidateCompactSerializedJWS(validJWS)

        let jws = try! JWS(compactSerialization: serializedJWS)
        let verifier = ECVerifier(algorithm: algorithm, publicKey: keyData.publicKey)

        guard let signingInput = [jws.header, jws.payload].asJOSESigningInput() else {
            XCTFail()
            return false
        }

        return (try? verifier.verify(signingInput, against: jws.signature)) ?? false
    }

    private func invalidateCompactSerializedJWS(_ validJWS: String) -> String {
        return validJWS.dropLast(7).appending("INVALID")
    }

    func testVerifying() {
        XCTAssertTrue(_testVerifying(algorithm: .ES256, keyData: p256))
        XCTAssertTrue(_testVerifying(algorithm: .ES384, keyData: p384))
        XCTAssertTrue(_testVerifying(algorithm: .ES512, keyData: p521))
    }

    func testVerifyingInvalid() {
        XCTAssertFalse(_testVerifying(algorithm: .ES256, keyData: p256, validSignature: false))
        XCTAssertFalse(_testVerifying(algorithm: .ES384, keyData: p384, validSignature: false))
        XCTAssertFalse(_testVerifying(algorithm: .ES512, keyData: p521, validSignature: false))
    }
}
