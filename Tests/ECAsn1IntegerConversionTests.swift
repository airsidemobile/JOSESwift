//
//  ECAsn1IntegerConversionTests.swift
//  Tests
//
//  Created by Martin Schwaighofer on 12.06.19.
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

import XCTest
@testable import JOSESwift

class ECAsn1IntegerConversionTests: XCTestCase {

    struct TestInteger {
        let raw: Data
        let asn1: Data
        let description: String
    }

    // one byte test integers
    let oneByteInts = [
        TestInteger(raw: Data([ 0x00 ]), asn1: Data([ 0x00 ]), description: "0"),
        TestInteger(raw: Data([ 0x01 ]), asn1: Data([ 0x01 ]), description: "1"),
        TestInteger(raw: Data([ 0x80 ]), asn1: Data([ 0x00, 0x80 ]), description: "128")
    ]

    // four byte test integers
    let fourByteInts = [
        TestInteger(raw: Data([ 0x00, 0x00, 0x00, 0x00 ]), asn1: Data([ 0x00 ]), description: "0"),
        TestInteger(raw: Data([ 0x00, 0x00, 0x00, 0x01 ]), asn1: Data([ 0x01 ]), description: "1"),
        TestInteger(raw: Data([ 0x00, 0x00, 0x00, 0x80 ]), asn1: Data([ 0x00, 0x80 ]), description: "128"),
        TestInteger(raw: Data([ 0x9B, 0x81, 0x03, 0x63 ]), asn1: Data([ 0x00, 0x9B, 0x81, 0x03, 0x63 ]), description: "high leading bit"),
        TestInteger(raw: Data([ 0x11, 0x81, 0x03, 0x63 ]), asn1: Data([ 0x11, 0x81, 0x03, 0x63 ]), description: "low leading bit"),
        TestInteger(raw: Data([ 0x00, 0x01, 0x03, 0x63 ]), asn1: Data([ 0x01, 0x03, 0x63 ]), description: "low leading byte followed by low leading bit"),
        TestInteger(raw: Data([ 0x00, 0x81, 0x03, 0x63 ]), asn1: Data([ 0x00, 0x81, 0x03, 0x63 ]), description: "low leading byte followed by high leading bit"),
        TestInteger(raw: Data([ 0x00, 0x00, 0x03, 0x63 ]), asn1: Data([ 0x03, 0x63 ]), description: "low leading bytes followed by low leading bit"),
        TestInteger(raw: Data([ 0x00, 0x00, 0x83, 0x63 ]), asn1: Data([ 0x00, 0x83, 0x63 ]), description: "low leading bytes followed by high leading bit"),
        TestInteger(raw: Data([ 0x11, 0x00, 0x00, 0x63 ]), asn1: Data([ 0x11, 0x00, 0x00, 0x63 ]), description: "intermediary low bytes"),
        TestInteger(raw: Data([ 0x9B, 0x81, 0x03, 0x00 ]), asn1: Data([ 0x00, 0x9B, 0x81, 0x03, 0x00 ]), description: "low tailing bytes")
    ]

    // 64 byte tests
    let hugeInt = TestInteger(
        raw: Data([
            0x06, 0xA5, 0x28, 0x53, 0xE9, 0x71, 0x64, 0x9F, 0x15, 0x20, 0x73, 0x7D, 0x9F, 0xF7, 0xE8, 0x36,
            0x86, 0xA0, 0x32, 0xD5, 0x73, 0xBD, 0x16, 0x2F, 0x0E, 0x0A, 0x71, 0xFD, 0x92, 0x93, 0x0E, 0x81,
            0x57, 0x62, 0x29, 0xFC, 0x49, 0x7C, 0x80, 0x82, 0x24, 0xBE, 0x04, 0x07, 0xE9, 0x85, 0xF2, 0xE2,
            0xBC, 0x22, 0xE9, 0xA9, 0xB9, 0xDB, 0x65, 0x64, 0x38, 0x07, 0x60, 0xB1, 0x7A, 0x20, 0x5E, 0x0D
            ]),
        asn1: Data([
            0x06, 0xA5, 0x28, 0x53, 0xE9, 0x71, 0x64, 0x9F, 0x15, 0x20, 0x73, 0x7D, 0x9F, 0xF7, 0xE8, 0x36,
            0x86, 0xA0, 0x32, 0xD5, 0x73, 0xBD, 0x16, 0x2F, 0x0E, 0x0A, 0x71, 0xFD, 0x92, 0x93, 0x0E, 0x81,
            0x57, 0x62, 0x29, 0xFC, 0x49, 0x7C, 0x80, 0x82, 0x24, 0xBE, 0x04, 0x07, 0xE9, 0x85, 0xF2, 0xE2,
            0xBC, 0x22, 0xE9, 0xA9, 0xB9, 0xDB, 0x65, 0x64, 0x38, 0x07, 0x60, 0xB1, 0x7A, 0x20, 0x5E, 0x0D
            ]),
        description: "64 bytes (huge)"
    )

    func testEncodeOneByteInts() {
        for int in oneByteInts {
            XCTAssertEqual(EC.Asn1IntegerConversion.fromRaw(int.raw), int.asn1, "Failure for \"\(int.description)\" example.")
        }
    }

    func testDecodeOneByteInts() {
        for int in oneByteInts {
            XCTAssertEqual(EC.Asn1IntegerConversion.toRaw(int.asn1, of: 1), int.raw, "Failure for \"\(int.description)\" example.")
        }
    }

    func testEncodeFourByteInts() {
        for int in fourByteInts {
            XCTAssertEqual(EC.Asn1IntegerConversion.fromRaw(int.raw), int.asn1, "Failure for \"\(int.description)\" example.")
        }
    }

    func testDecodeFourByteInts() {
        for int in fourByteInts {
            XCTAssertEqual(EC.Asn1IntegerConversion.toRaw(int.asn1, of: 4), int.raw, "Failure for \"\(int.description)\" example.")
        }
    }

    func testEncodeHugeInt() {
        XCTAssertEqual(EC.Asn1IntegerConversion.fromRaw(hugeInt.raw), hugeInt.asn1)
    }

    func testDecodeHugeInt() {
        XCTAssertEqual(EC.Asn1IntegerConversion.toRaw(hugeInt.asn1, of: 64), hugeInt.raw)
    }
}
