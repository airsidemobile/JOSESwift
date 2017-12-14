//
//  JWEHeaderTests.swift
//  Tests
//
//  Created by Carol Capek on 31.10.17.
//

import XCTest
@testable import SwiftJOSE

class JWEHeaderTests: XCTestCase {
    let parameterDict = ["alg": "RSA1_5", "enc": "A256CBC-HS512"]
    let parameterData = try! JSONSerialization.data(withJSONObject: ["alg": "RSA1_5", "enc": "A256CBC-HS512"], options: [])

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testInitWithParameters() {
        let header = try! JWEHeader(parameters: parameterDict, headerData: parameterData)

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricEncryptionAlgorithm.AES256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricEncryptionAlgorithm.RSAPKCS.rawValue)
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDict, options: []))
    }

    func testInitWithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDict, options: [])
        let header = JWEHeader(data)!

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricEncryptionAlgorithm.AES256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricEncryptionAlgorithm.RSAPKCS.rawValue)
        XCTAssertEqual(header.data(), data)
    }

    func testInitWithAlgAndEnc() {
        let header = JWEHeader(algorithm: .RSAPKCS, encryptionAlgorithm: .AES256CBCHS512)

        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDict, options: []))
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricEncryptionAlgorithm.RSAPKCS.rawValue)
        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricEncryptionAlgorithm.AES256CBCHS512.rawValue)

        XCTAssertNotNil(header.algorithm)
        XCTAssertNotNil(header.encryptionAlgorithm)
        XCTAssertEqual(header.algorithm!, .RSAPKCS)
        XCTAssertEqual(header.encryptionAlgorithm!, .AES256CBCHS512)
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
