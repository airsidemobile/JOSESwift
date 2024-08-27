//
//  PBES2Tests.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 11.12.23.
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

class PBES2Tests: XCTestCase {
    /// Tests the PBES2 key derivation with the test data provided in the [RFC-7517](https://www.rfc-editor.org/rfc/rfc7517#appendix-C.4).
    func testDeriveWrappingKey() throws {
        let password = "Thus from my lips, by yours, my sin is purged."
        let saltInput = Data([217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215])
        let iterationCount = 4096
        let derivedKey = try PBES2.deriveWrappingKey(password: password, algorithm: .PBES2_HS256_A128KW, saltInput: saltInput, iterationCount: iterationCount)
        let expectedKey = Data([110, 171, 169, 92, 129, 92, 109, 117, 233, 242, 116, 233, 170, 14, 24, 75])
        XCTAssertEqual(derivedKey, expectedKey)
    }
}
