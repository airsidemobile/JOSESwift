// swiftlint:disable force_unwrapping
//
//  JWEHeaderTests.swift
//  Tests
//
//  Created by Carol Capek on 31.10.17.
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

class JWEHeaderTests: XCTestCase {
    let parameterDictRSA = ["alg": "RSA1_5", "enc": "A256CBC-HS512"]
    let parameterDataRSA = try! JSONSerialization.data(withJSONObject: ["alg": "RSA1_5", "enc": "A256CBC-HS512"], options: [])

    let parameterDictRSAOAEP = ["alg": "RSA-OAEP", "enc": "A256CBC-HS512"]
    let parameterDataRSAOAEP = try! JSONSerialization.data(withJSONObject: ["alg": "RSA-OAEP", "enc": "A256CBC-HS512"], options: [])

    let parameterDictRSAOAEP256 = ["alg": "RSA-OAEP-256", "enc": "A256CBC-HS512"]
    let parameterDataRSAOAEP256 = try! JSONSerialization.data(withJSONObject: ["alg": "RSA-OAEP-256", "enc": "A256CBC-HS512"], options: [])

    let parameterDictDirect = ["alg": "dir", "enc": "A256CBC-HS512"]
    let parameterDataDirect = try! JSONSerialization.data(withJSONObject: ["alg": "dir", "enc": "A256CBC-HS512"], options: [])

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testInitRSA1WithParameters() {
        let header = try! JWEHeader(parameters: parameterDictRSA)

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSA1_5.rawValue)
        XCTAssertEqual(header.data().count, try! JSONSerialization.data(withJSONObject: parameterDictRSA, options: []).count)
    }

    func testInitRSAOAEPWithParameters() {
        let header = try! JWEHeader(parameters: parameterDictRSAOAEP)

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSAOAEP.rawValue)
        XCTAssertEqual(header.data().count, try! JSONSerialization.data(withJSONObject: parameterDictRSAOAEP, options: []).count)
    }

    func testInitRSAOAEP256WithParameters() {
        let header = try! JWEHeader(parameters: parameterDictRSAOAEP256)

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSAOAEP256.rawValue)
        XCTAssertEqual(header.data().count, try! JSONSerialization.data(withJSONObject: parameterDictRSAOAEP256, options: []).count)
    }

    func testInitRSA1WithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDictRSA, options: [])
        let header = JWEHeader(data)!

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSA1_5.rawValue)
        XCTAssertEqual(header.data(), data)
    }

    func testInitRSAOAEPWithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDictRSAOAEP, options: [])
        let header = JWEHeader(data)!

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSAOAEP.rawValue)
        XCTAssertEqual(header.data(), data)
    }

    func testInitRSAOAEP256WithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDictRSAOAEP256, options: [])
        let header = JWEHeader(data)!

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSAOAEP256.rawValue)
        XCTAssertEqual(header.data(), data)
    }

    func testInitDirectWithParameters() {
        let header = try! JWEHeader(parameters: parameterDictDirect, headerData: parameterDataDirect)

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.direct.rawValue)
        XCTAssertEqual(header.data().count, try! JSONSerialization.data(withJSONObject: parameterDictDirect, options: []).count)
    }

    func testInitDirectWithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDictDirect, options: [])
        let header = JWEHeader(data)!

        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.direct.rawValue)
        XCTAssertEqual(header.data(), data)
    }

    func testInitWithAlgAndEncRSA1() {
        let header = JWEHeader(algorithm: .RSA1_5, encryptionAlgorithm: .A256CBCHS512)

        XCTAssertEqual(header.data().count, try! JSONSerialization.data(withJSONObject: parameterDictRSA, options: []).count)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSA1_5.rawValue)
        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)

        XCTAssertNotNil(header.algorithm)
        XCTAssertNotNil(header.encryptionAlgorithm)
        XCTAssertEqual(header.algorithm!, .RSA1_5)
        XCTAssertEqual(header.encryptionAlgorithm!, .A256CBCHS512)
    }

    func testInitWithAlgAndEncRSAOAEP() {
        let header = JWEHeader(algorithm: .RSAOAEP, encryptionAlgorithm: .A256CBCHS512)

        XCTAssertEqual(header.data().count, try! JSONSerialization.data(withJSONObject: parameterDictRSAOAEP, options: []).count)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSAOAEP.rawValue)
        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)

        XCTAssertNotNil(header.algorithm)
        XCTAssertNotNil(header.encryptionAlgorithm)
        XCTAssertEqual(header.algorithm!, .RSAOAEP)
        XCTAssertEqual(header.encryptionAlgorithm!, .A256CBCHS512)
    }

    func testInitWithAlgAndEncRSAOAEP256() {
        let header = JWEHeader(algorithm: .RSAOAEP256, encryptionAlgorithm: .A256CBCHS512)

        XCTAssertEqual(header.data().count, try! JSONSerialization.data(withJSONObject: parameterDictRSAOAEP256, options: []).count)
        XCTAssertEqual(header.parameters["alg"] as? String, AsymmetricKeyAlgorithm.RSAOAEP256.rawValue)
        XCTAssertEqual(header.parameters["enc"] as? String, SymmetricKeyAlgorithm.A256CBCHS512.rawValue)

        XCTAssertNotNil(header.algorithm)
        XCTAssertNotNil(header.encryptionAlgorithm)
        XCTAssertEqual(header.algorithm!, .RSAOAEP256)
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

    func testInitDirectlyWithMissingRequiredAlgParameter() {
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
            _ = try JWEHeader(parameters: ["typ": JOSEDeserializer()], headerData: Data())
        } catch HeaderParsingError.headerIsNotValidJSONObject {
            XCTAssertTrue(true)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testSetNonRequiredHeaderParametersInJWEHeader() {
        let jku: URL? = nil
        let jwk = "jwk"
        let kid = "kid"
        let x5u: URL? = nil
        let x5c = ["key1", "key2"]
        let x5t = "x5t"
        let x5tS256 = "x5tS256"
        let typ = "typ"
        let cty = "cty"
        let crit = ["crit1", "crit2"]
        let zip = "DEF"

        var header = JWEHeader(algorithm: .RSA1_5, encryptionAlgorithm: .A256CBCHS512)
        header.jku = jku
        header.jwk = jwk
        header.kid = kid
        header.x5u = x5u
        header.x5c = x5c
        header.x5t = x5t
        header.x5tS256 = x5tS256
        header.typ = typ
        header.cty = cty
        header.crit = crit
        header.zip = zip

        XCTAssertEqual(header.data().count, try! JSONSerialization.data(withJSONObject: header.parameters, options: []).count)

        XCTAssertEqual(header.parameters["jku"] as? URL, jku)
        XCTAssertEqual(header.jku, jku)

        XCTAssertEqual(header.parameters["jwk"] as? String, jwk)
        XCTAssertEqual(header.jwk, jwk)

        XCTAssertEqual(header.parameters["kid"] as? String, kid)
        XCTAssertEqual(header.kid, kid)

        XCTAssertEqual(header.parameters["x5u"] as? URL, x5u)
        XCTAssertEqual(header.x5u, x5u)

        XCTAssertEqual(header.parameters["x5c"] as? [String], x5c)
        XCTAssertEqual(header.x5c, x5c)

        XCTAssertEqual(header.parameters["x5t"] as? String, x5t)
        XCTAssertEqual(header.x5t, x5t)

        XCTAssertEqual(header.parameters["x5tS256"] as? String, x5tS256)
        XCTAssertEqual(header.x5tS256, x5tS256)

        XCTAssertEqual(header.parameters["typ"] as? String, typ)
        XCTAssertEqual(header.typ, typ)

        XCTAssertEqual(header.parameters["cty"] as? String, cty)
        XCTAssertEqual(header.cty, cty)

        XCTAssertEqual(header.parameters["crit"] as? [String], crit)
        XCTAssertEqual(header.crit, crit)

        XCTAssertEqual(header.parameters["zip"] as? String, zip)
        XCTAssertEqual(header.zip, zip)
        XCTAssertEqual(header.compressionAlgorithm, CompressionAlgorithm.DEFLATE)

        header.zip = "NONE"
        XCTAssertEqual(header.compressionAlgorithm, CompressionAlgorithm.NONE)

        header.zip = "GZIP"
        XCTAssertEqual(header.compressionAlgorithm, nil)
    }
}
