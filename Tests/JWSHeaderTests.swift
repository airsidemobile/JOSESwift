//
//  JWSHeaderTests.swift
//  Tests
//
//  Created by Carol Capek on 30.10.17.
//

import XCTest
@testable import SwiftJOSE

class JWSHeaderTests: XCTestCase {
    let parameterDict = ["alg": "\(SigningAlgorithm.RS512.rawValue)"]
    let parameterData = try! JSONSerialization.data(withJSONObject: ["alg": "\(SigningAlgorithm.RS512.rawValue)"], options: [])

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

        XCTAssertEqual(header.parameters["alg"] as? String, SigningAlgorithm.RS512.rawValue)
        XCTAssertEqual(header.data(), data)
    }

    func testInitWithAlg() {
        let header = JWSHeader(algorithm: .RS512)

        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDict, options: []))
        XCTAssertEqual(header.parameters["alg"] as? String, SigningAlgorithm.RS512.rawValue)

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
