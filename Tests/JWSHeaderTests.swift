// swiftlint:disable force_unwrapping
//
//  JWSHeaderTests.swift
//  Tests
//
//  Created by Carol Capek on 30.10.17.
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
        XCTAssertEqual(header.data().count, try! JSONSerialization.data(withJSONObject: parameterDict, options: []).count)
    }

    func testInitWithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDict, options: [])
        let header = JWSHeader(data)!

        XCTAssertEqual(header.parameters["alg"] as? String, SignatureAlgorithm.RS512.rawValue)
        XCTAssertEqual(header.data(), data)
    }

    func testInitWithAlg() {
        let header = JWSHeader(algorithm: .RS512)

        XCTAssertEqual(header.data().count, try! JSONSerialization.data(withJSONObject: parameterDict, options: []).count)
        XCTAssertEqual(header.parameters["alg"] as? String, SignatureAlgorithm.RS512.rawValue)

        XCTAssertNotNil(header.algorithm)
        XCTAssertEqual(header.algorithm!, .RS512)
    }

    func testInitDirectlyWithMissingRequiredParameters() {
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

    func testInitWithMissingRequiredParameters() {
        do {
            _ = try JWSHeader(parameters: ["typ": "JWT"])
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

    func testSetNonRequiredHeaderParametersInJWSHeader() {
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

        var header = JWSHeader(algorithm: .RS512)
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
    }

    func testJwkTypedHeaderParamEC() throws {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]

        var error: Unmanaged<CFError>?

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print(error!)
            return
        }

        let publicKey = SecKeyCopyPublicKey(privateKey)!

        let jwk = try ECPublicKey(publicKey: publicKey)

        var header = JWSHeader(algorithm: .ES256)

        header.jwkTyped = jwk

        // The actual 'jwk' parameter is expected to be a dictionary
        let jwkParam = header.parameters["jwk"] as? [String: String]
        XCTAssertNotNil(jwkParam)

        let headerJwk = header.jwkTyped as? ECPublicKey
        XCTAssertNotNil(headerJwk)
        XCTAssertEqual(jwk.keyType, headerJwk?.keyType)
        XCTAssertEqual(jwk.crv, headerJwk?.crv)
        XCTAssertEqual(jwk.x, headerJwk?.x)
        XCTAssertEqual(jwk.y, headerJwk?.y)
    }

    func testJwkTypedHeaderParamRSA() throws {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]

        var error: Unmanaged<CFError>?

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print(error!)
            return
        }

        let publicKey = SecKeyCopyPublicKey(privateKey)!

        let jwk = try RSAPublicKey(publicKey: publicKey)

        var header = JWSHeader(algorithm: .ES256)

        header.jwkTyped = jwk

        // The actual 'jwk' parameter is expected to be a dictionary
        let jwkParam = header.parameters["jwk"] as? [String: String]
        XCTAssertNotNil(jwkParam)

        let headerJwk = header.jwkTyped as? RSAPublicKey
        XCTAssertNotNil(headerJwk)
        XCTAssertEqual(jwk.keyType, headerJwk?.keyType)
        XCTAssertEqual(jwk.exponent, headerJwk?.exponent)
        XCTAssertEqual(jwk.modulus, headerJwk?.modulus)
    }
}
