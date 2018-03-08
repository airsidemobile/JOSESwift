//
//  JWSHeaderTests.swift
//  Tests
//
//  Created by Carol Capek on 30.10.17.
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

class JWSHeaderTests: XCTestCase {
    let parameterDict = ["alg": "\(SignatureAlgorithm.RS512.rawValue)"]
    let parameterData = try! JSONSerialization.data(withJSONObject: ["alg": "\(SignatureAlgorithm.RS512.rawValue)"], options: [])

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testInitWithParameters() {
        let header = try! JWSHeader(parameters: parameterDict, headerData: parameterData)

        XCTAssertEqual(header.parameters["alg"] as? String, parameterDict["alg"])
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDict, options: []))
    }

    func testInitWithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDict, options: [])
        let header = JWSHeader(data)!

        XCTAssertEqual(header.parameters["alg"] as? String, SignatureAlgorithm.RS512.rawValue)
        XCTAssertEqual(header.data(), data)
    }

    func testInitWithAlg() {
        let header = JWSHeader(algorithm: .RS512)

        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDict, options: []))
        XCTAssertEqual(header.parameters["alg"] as? String, SignatureAlgorithm.RS512.rawValue)

        XCTAssertNotNil(header.algorithm)
        XCTAssertEqual(header.algorithm!, .RS512)
    }

    func testInitWithMissingRequiredParameters() {
        do {
            _ = try JWSHeader(parameters: ["typ": "JWT"], headerData: try! JSONSerialization.data(withJSONObject: ["typ": "JWT"], options: []))
        } catch HeaderParsingError.requiredHeaderParameterMissing(let parameter) {
            XCTAssertEqual(parameter, "alg")
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testInitWithInvalidJSONDictionary() {
        do {
            _ = try JWSHeader(parameters: ["typ": JOSEDeserializer()], headerData: Data())
        } catch HeaderParsingError.headerIsNotValidJSONObject {
            XCTAssertTrue(true)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

}
