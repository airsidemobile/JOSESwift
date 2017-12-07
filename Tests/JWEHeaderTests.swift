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

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testInitWithParameters() {
        let header = try! JWEHeader(parameters: parameterDict)

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
            _ = try JWEHeader(parameters: ["alg": "RSA-OAEP"])
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
            _ = try JWEHeader(parameters: ["enc": "something"])
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
            _ = try JWEHeader(parameters: ["typ": JOSEDeserializer()])
        } catch HeaderParsingError.headerIsNotValidJSONObject {
            XCTAssertTrue(true)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

}
