//
//  HMACVerifierTests.swift
//  Tests
//
//  Created by Tobias Hagemann on 14.04.21.
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

class HMACVerifierTests: HMACCryptoTestCase {
    private func _testVerifying(algorithm: SignatureAlgorithm, expectedSignature: Data) {
        let verifier = HMACVerifier(algorithm: algorithm, key: testKey)
        XCTAssertTrue(try! verifier.verify(testData, against: expectedSignature))
    }

    func testVerifying() {
        _testVerifying(algorithm: .HS256, expectedSignature: hmac256TestOutput)
        _testVerifying(algorithm: .HS384, expectedSignature: hmac384TestOutput)
        _testVerifying(algorithm: .HS512, expectedSignature: hmac512TestOutput)
    }
}
