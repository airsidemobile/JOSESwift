// swiftlint:disable force_unwrapping
//
//  HMACTests.swift
//  Tests
//
//  Created by Carol Capek on 05.12.17.
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

class HMACTests: HMACCryptoTestCase {
    func testHMAC256Calculation() {
        let hmacOutput = try! HMAC.calculate(from: testData, with: testKey, using: .SHA256)

        XCTAssertEqual(hmacOutput, hmac256TestOutput)
    }

    func testHMAC256CalculationWithFalseKey() {
        let falseKey = "abcdefg".hexadecimalToData()!

        let hmacOutput = try! HMAC.calculate(from: testData, with: falseKey, using: .SHA256)

        XCTAssertNotEqual(hmacOutput, hmac256TestOutput)
    }

    func testHMAC256CalculationWithFalseData() {
        let falseData = "abcdefg".hexadecimalToData()!

        let hmacOutput = try! HMAC.calculate(from: falseData, with: testKey, using: .SHA256)

        XCTAssertNotEqual(hmacOutput, hmac256TestOutput)
    }

    func testHMAC384Calculation() {
        let hmacOutput = try! HMAC.calculate(from: testData, with: testKey, using: .SHA384)

        XCTAssertEqual(hmacOutput, hmac384TestOutput)
    }

    func testHMAC384CalculationWithFalseKey() {
        let falseKey = "abcdefg".hexadecimalToData()!

        let hmacOutput = try! HMAC.calculate(from: testData, with: falseKey, using: .SHA384)

        XCTAssertNotEqual(hmacOutput, hmac384TestOutput)
    }

    func testHMAC384CalculationWithFalseData() {
        let falseData = "abcdefg".hexadecimalToData()!

        let hmacOutput = try! HMAC.calculate(from: falseData, with: testKey, using: .SHA384)

        XCTAssertNotEqual(hmacOutput, hmac384TestOutput)
    }

    func testHMAC512Calculation() {
        let hmacOutput = try! HMAC.calculate(from: testData, with: testKey, using: .SHA512)

        XCTAssertEqual(hmacOutput, hmac512TestOutput)
    }

    func testHMAC512CalculationWithFalseKey() {
        let falseKey = "abcdefg".hexadecimalToData()!

        let hmacOutput = try! HMAC.calculate(from: testData, with: falseKey, using: .SHA512)

        XCTAssertNotEqual(hmacOutput, hmac512TestOutput)
    }

    func testHMAC512CalculationWithFalseData() {
        let falseData = "abcdefg".hexadecimalToData()!

        let hmacOutput = try! HMAC.calculate(from: falseData, with: testKey, using: .SHA512)

        XCTAssertNotEqual(hmacOutput, hmac512TestOutput)
    }
}
// swiftlint:enable force_unwrapping
