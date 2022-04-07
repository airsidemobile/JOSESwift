// swiftlint:disable force_unwrapping
//
//  JWSSigningInputTest.swift
//  Tests
//
//  Created by Daniel Egger on 07.12.17.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
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

class JWSSigningInputTest: XCTestCase {

    let header: JWSHeader = JWSHeader("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}".data(using: .utf8)!)!
    let payload: Payload = Payload("{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}".data(using: .utf8)!)

    let expectedSigningInput: [UInt8] = [
        101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81,
        105, 76, 65, 48, 75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74,
        73, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51,
        77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67,
        74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84,
        107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100,
        72, 65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76,
        109, 78, 118, 98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73,
        106, 112, 48, 99, 110, 86, 108, 102, 81
    ]

    func testSigningInputComputation() throws {
        let signingInput: [UInt8] = Array(try JWSSigningInput(header: header, payload: payload).signingInput())
        XCTAssertEqual(signingInput, expectedSigningInput)
    }

}
