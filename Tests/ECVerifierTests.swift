//
//  ECVerifierTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 08.10.17.
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

class ECVerifierTests: ECCryptoTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func _testVerifying(algorithm: SignatureAlgorithm, keyData: ECTestKeyData) {
        let jws = try! JWS(compactSerialization: keyData.compactSerializedJWSConst)
        let verifier = ECVerifier(algorithm: algorithm, publicKey: keyData.publicKey)

        guard let signingInput = [jws.header, jws.payload].asJOSESigningInput() else {
            XCTFail()
            return
        }

        XCTAssertTrue(try! verifier.verify(signingInput, against: jws.signature))
    }

    func testVerifying() {
        _testVerifying(algorithm: .ES256, keyData: p256)
        _testVerifying(algorithm: .ES384, keyData: p384)
        _testVerifying(algorithm: .ES512, keyData: p521)
    }

}
