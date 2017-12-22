//
//  HMACTests.swift
//  Tests
//
//  Created by Carol Capek on 05.12.17.
//

import XCTest
@testable import SwiftJOSE

class HMACTests: CryptoTestCase {
    let testKey = "0102030405060708090a0b0c0d0e0f10111213141516171819".hexadecimalToData()!
    let testData = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".hexadecimalToData()!
    let hmacTestOutput = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd".hexadecimalToData()!

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    /**
     [RFC-4231]: https://tools.ietf.org/html/rfc4231 "HMAC Test data"
     
     Tests the HMAC calculation implementation for HMAC_SHA_512 with the test data provided in the [RFC-4231].
     */
    func testHMACCalculation() {
        let hmacOutput = HMAC.calculate(from: testData, with: testKey, using: .SHA512)

        XCTAssertEqual(hmacOutput, hmacTestOutput)
    }

    /**
     [RFC-4231]: https://tools.ietf.org/html/rfc4231 "HMAC Test data"
     
     Tests the HMAC calculation implementation for HMAC_SHA_512 with the test data provided in the [RFC-4231].
     */
    func testHMACCalculationWithFalseKey() {
        let falseKey = "abcdefg".hexadecimalToData()!

        let hmacOutput = HMAC.calculate(from: testData, with: falseKey, using: .SHA512)

        XCTAssertNotEqual(hmacOutput, hmacTestOutput)
    }

    /**
     [RFC-4231]: https://tools.ietf.org/html/rfc4231 "HMAC Test data"
     
     Tests the HMAC calculation implementation for HMAC_SHA_512 with the test data provided in the [RFC-4231].
     */
    func testHMACCalculationWithFalseData() {
        let falseData = "abcdefg".hexadecimalToData()!

        let hmacOutput = HMAC.calculate(from: falseData, with: testKey, using: .SHA512)

        XCTAssertNotEqual(hmacOutput, hmacTestOutput)
    }
}
