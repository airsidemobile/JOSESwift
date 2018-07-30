//
//  JWEHeaderTests.swift
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

class JWEHeaderTests: XCTestCase {
    let parameterDictRSA = ["alg": "RSA1_5", "enc": "A256CBC-HS512"]
    let parameterDataRSA = try! JSONSerialization.data(withJSONObject: ["alg": "RSA1_5", "enc": "A256CBC-HS512"], options: [])

    let parameterDictDirect = ["alg": "dir", "enc": "A256CBC-HS512"]
    let parameterDataDirect = try! JSONSerialization.data(withJSONObject: ["alg": "dir", "enc": "A256CBC-HS512"], options: [])

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testInitRSAWithParameters() {
        let header = try! JWEHeader(parameters: parameterDictRSA, headerData: parameterDataRSA)

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSA1_5.rawValue)
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDictRSA, options: []))
    }

    func testInitRSAWithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDictRSA, options: [])
        let header = JWEHeader(data)!

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSA1_5.rawValue)
        XCTAssertEqual(header.data(), data)
    }

    func testInitDirectWithParameters() {
        let header = try! JWEHeader(parameters: parameterDictDirect, headerData: parameterDataDirect)

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.direct.rawValue)
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDictDirect, options: []))
    }

    func testInitDirectWithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDictDirect, options: [])
        let header = JWEHeader(data)!

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.direct.rawValue)
        XCTAssertEqual(header.data(), data)
    }

    func testInitWithAlgAndEnc() {
        let header = JWEHeader(algorithm: .RSA1_5, encryptionAlgorithm: .A256CBCHS512)

        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDictRSA, options: []))
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSA1_5.rawValue)
        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)

        XCTAssertNotNil(header.algorithm)
        XCTAssertNotNil(header.encryptionAlgorithm)
        XCTAssertEqual(header.algorithm!, .RSA1_5)
        XCTAssertEqual(header.encryptionAlgorithm!, .A256CBCHS512)
    }

    func testInitWithMissingRequiredEncParameter() {
        do {
            _ = try JWEHeader(parameters: ["alg": "RSA-OAEP"], headerData: try! JSONSerialization.data(withJSONObject: ["alg": "RSA1_5"], options: []))
        } catch HeaderParsingError.requiredHeaderParameterMissing(let parameter) {
            XCTAssertEqual(parameter, "enc")
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testInitWithMissingRequiredAlgParameter() {
        do {
            _ = try JWEHeader(parameters: ["enc": "something"], headerData: try! JSONSerialization.data(withJSONObject: ["enc": "something"], options: []))
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
            _ = try JWEHeader(parameters: ["typ": JOSEDeserializer()], headerData: Data())
        } catch HeaderParsingError.headerIsNotValidJSONObject {
            XCTAssertTrue(true)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

}
