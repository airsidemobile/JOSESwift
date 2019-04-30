// swiftlint:disable force_unwrapping
//
//  DataExtensionTests.swift
//  Tests
//
//  Created by Carol Capek on 31.10.17.
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

class DataExtensionTests: XCTestCase {
    let validBase64URLTestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIHdoZXJlIHRoZSBiYXNlNjQgcmVwcmVzZW50YXRpb24gY29udGFpbnMgYSA9IGFzIHBhZGRpbmc"
    let testString = "This is a test string where the base64 representation contains a = as padding"
    let invalidLengthBase64URL = "cZT4CL5sc"
    let notUTF8Data = "8J-YhQ".data(using: String.Encoding.unicode)!

    let edgeCases = [
        // Does "_" <-> "/" replacement work?
        "_": (unencoded: "Do you have no question?".data(using: .utf8)!, base64URLEncoded: "RG8geW91IGhhdmUgbm8gcXVlc3Rpb24_".data(using: .utf8)!),
        // Does "+" <-> "-" replacement work?
        "-": (unencoded: "😅".data(using: .utf8)!, base64URLEncoded: "8J-YhQ".data(using: .utf8)!),
        // Does "=" <-> "" replacement work?
        "=": (unencoded: "I'm not the most important test.".data(using: .utf8)!, base64URLEncoded: "SSdtIG5vdCB0aGUgbW9zdCBpbXBvcnRhbnQgdGVzdC4".data(using: .utf8)!),
        // Does "==" <-> "" replacement work?
        "==": (unencoded: "testing the test".data(using: .utf8)!, base64URLEncoded: "dGVzdGluZyB0aGUgdGVzdA".data(using: .utf8)!)
    ]

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testBase64URLStringInit() {
        let data = Data(base64URLEncoded: validBase64URLTestString)

        XCTAssertNotNil(data)
        XCTAssertEqual(data, testString.data(using: .utf8))
    }

    func testInvalidLengthBase64URLStringInit() {
        let data = Data(base64URLEncoded: invalidLengthBase64URL)

        XCTAssertNil(data)
    }

    func testBase64URLDataInit() {
        let data = Data(base64URLEncoded: validBase64URLTestString.data(using: .utf8)!)

        XCTAssertNotNil(data)
        XCTAssertEqual(data, testString.data(using: .utf8))
    }

    func testInvalidLengthBase64URLDataInit() {
        let data = Data(base64URLEncoded: invalidLengthBase64URL.data(using: .utf8)!)

        XCTAssertNil(data)
    }

    func testDataToBase64URLString() {
        let data = testString.data(using: .utf8)!
        let base64URLString = data.base64URLEncodedString()

        XCTAssertEqual(base64URLString, validBase64URLTestString)
    }

    func testDataToBase64URLData() {
        let data = testString.data(using: .utf8)!
        let base64URLData = data.base64URLEncodedData()

        XCTAssertEqual(base64URLData, validBase64URLTestString.data(using: .utf8)!)
    }

    func testInitWithNonUTF8Data() {
        let base64URL = Data(base64URLEncoded: notUTF8Data)

        XCTAssertNil(base64URL)
    }

    func testUnderscoreDecoding() {
        let unencoded = Data(base64URLEncoded: edgeCases["_"]!.base64URLEncoded)

        XCTAssertNotNil(unencoded)
        XCTAssertEqual(unencoded, edgeCases["_"]!.unencoded)
    }

    func testDashDecoding() {
        let unencoded = Data(base64URLEncoded: edgeCases["-"]!.base64URLEncoded)

        XCTAssertNotNil(unencoded)
        XCTAssertEqual(unencoded, edgeCases["-"]!.unencoded)
    }

    func testOnePaddingDecoding() {
        let unencoded = Data(base64URLEncoded: edgeCases["="]!.base64URLEncoded)

        XCTAssertNotNil(unencoded)
        XCTAssertEqual(unencoded, edgeCases["="]!.unencoded)
    }

    func testTwoPaddingDecoding() {
        let unencoded = Data(base64URLEncoded: edgeCases["=="]!.base64URLEncoded)

        XCTAssertNotNil(unencoded)
        XCTAssertEqual(unencoded, edgeCases["=="]!.unencoded)
    }

    func testUnderscoreEncoding() {
        let encoded = edgeCases["_"]!.unencoded.base64URLEncodedData()

        XCTAssertNotNil(encoded)
        XCTAssertEqual(encoded, edgeCases["_"]!.base64URLEncoded)
    }

    func testDashEncoding() {
        let encoded = edgeCases["-"]!.unencoded.base64URLEncodedData()

        XCTAssertNotNil(encoded)
        XCTAssertEqual(encoded, edgeCases["-"]!.base64URLEncoded)
    }

    func testOnePaddingEncoding() {
        let encoded = edgeCases["="]!.unencoded.base64URLEncodedData()

        XCTAssertNotNil(encoded)
        XCTAssertEqual(encoded, edgeCases["="]!.base64URLEncoded)
    }

    func testTwoPaddingEncoding() {
        let encoded = edgeCases["=="]!.unencoded.base64URLEncodedData()

        XCTAssertNotNil(encoded)
        XCTAssertEqual(encoded, edgeCases["=="]!.base64URLEncoded)
    }

    func testByteLengthAsOctetHexData() {
        let testData = "54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63 69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20 4b 65 72 63 6b 68 6f 66 66 73".hexadecimalToData()!
        let testDataLengthAsOctetHex = Data([ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x50 ])

        let dataLength = testData.getByteLengthAsOctetHexData()

        XCTAssertEqual(testDataLengthAsOctetHex, dataLength)
    }

    func testFalseByteLengthAsOctetHexData() {
        let testData = "54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63 69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20 4b 65 72 63 6b 68 6f 66 66 73".hexadecimalToData()!
        let falseTestDataLengthAsOctetHex = Data([ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x50 ])

        let dataLength = testData.getByteLengthAsOctetHexData()

        XCTAssertNotEqual(falseTestDataLengthAsOctetHex, dataLength)
    }
}
