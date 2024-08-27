// swiftlint:disable force_unwrapping
//
//  JWSHeaderTests.swift
//  Tests
//
//  Created by Carol Capek on 30.10.17.
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
//

import XCTest
@testable import JOSESwift

class JWSHeaderTests: XCTestCase {
    let parameterDict = ["alg": "\(SignatureAlgorithm.RS512.rawValue)"]
    let parameterData = try! JSONSerialization.data(withJSONObject: ["alg": "\(SignatureAlgorithm.RS512.rawValue)"], options: [.sortedKeys])

    func testInitWithParameters() {
        let header = try! JWSHeader(parameters: parameterDict, headerData: parameterData)

        XCTAssertEqual(header.parameters["alg"] as? String, parameterDict["alg"])
        XCTAssertEqual(header.data().count, parameterData.count)
    }

    func testInitWithData() {
        let data = parameterData
        let header = JWSHeader(data)!

        XCTAssertEqual(header.parameters["alg"] as? String, SignatureAlgorithm.RS512.rawValue)
        XCTAssertEqual(header.data(), data)
    }

    func testInitWithAlg() {
        let header = JWSHeader(algorithm: .RS512)

        XCTAssertEqual(header.data().count, parameterData.count)
        XCTAssertEqual(header.parameters["alg"] as? String, SignatureAlgorithm.RS512.rawValue)

        XCTAssertNotNil(header.algorithm)
        XCTAssertEqual(header.algorithm!, .RS512)
    }

    func testInitDirectlyWithMissingRequiredParameters() {
        do {
            _ = try JWSHeader(
                parameters: ["typ": "JWT"],
                headerData: try! JSONSerialization.data(withJSONObject: ["typ": "JWT"], options: [.sortedKeys])
            )
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

        XCTAssertEqual(header.data().count, try! JSONSerialization.data(withJSONObject: header.parameters, options: [.sortedKeys]).count)

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

    func testSettingAndGettingPublicPrivateHeaderParameters() throws {
        var header = JWSHeader(algorithm: .RS512)

        // registered header parameter (RFC-7516, 4.1)
        try header.set("123", forParameter: "kid")

        // public or private header parameters (RFC-7516, 4.2 and 4.3)
        try header.set("string", forParameter: "string")
        try header.set(Float.pi, forParameter: "float")
        try header.set(Double.pi, forParameter: "double")
        try header.set(Int.max, forParameter: "int")
        try header.set(true, forParameter: "bool")
        try header.set(["one", "two", "three"], forParameter: "arary")
        try header.set(["one": 1, "two": 2, "three": 3], forParameter: "dict")

        // all parameters can be retrieved
        XCTAssertEqual(header.get(parameter: "alg") as? String, SignatureAlgorithm.RS512.rawValue)
        XCTAssertEqual(header.get(parameter: "kid") as? String, "123")
        XCTAssertEqual(header.get(parameter: "string") as! String, "string")
        XCTAssertEqual(header.get(parameter: "float") as! Float, Float.pi)
        XCTAssertEqual(header.get(parameter: "double") as! Double, Double.pi)
        XCTAssertEqual(header.get(parameter: "int") as! Int, Int.max)
        XCTAssertEqual(header.get(parameter: "bool") as! Bool, true)
        XCTAssertEqual(header.get(parameter: "arary") as! [String], ["one", "two", "three"])
        XCTAssertEqual(header.get(parameter: "dict") as! [String: Int], ["one": 1, "two": 2, "three": 3])

        // backing data representation is as expected
        var expectedValue = parameterDict as [String: Any]
        expectedValue["kid"] = "123"
        expectedValue["string"] = "string"
        expectedValue["float"] = Float.pi
        expectedValue["double"] = Double.pi
        expectedValue["int"] = Int.max
        expectedValue["bool"] = true
        expectedValue["arary"] = ["one", "two", "three"]
        expectedValue["dict"] = ["one": 1, "two": 2, "three": 3]
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: expectedValue, options: [.sortedKeys]))

        // registered parameters can bre retrieved via typed computed properties
        XCTAssertNotNil(header.algorithm)
        XCTAssertNotNil(header.kid)
        XCTAssertEqual(header.algorithm!, .RS512)
        XCTAssertEqual(header.kid!, "123")
    }

    func testSettingInvalidPublicPrivateHeaderParameters() throws {
        var header = JWSHeader(algorithm: .RS512)

        // valid parameters work
        try header.set("123", forParameter: "kid")
        try header.set("string", forParameter: "string")

        XCTAssertEqual(header.get(parameter: "kid") as? String, "123")
        XCTAssertEqual(header.get(parameter: "string") as! String, "string")

        // invalid parameters don't work and don't interfere with valid parameters
        XCTAssertThrowsError(try header.set("data".data(using: .utf8)!, forParameter: "data")) { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.invalidHeaderParameterValue)
        }
        XCTAssertThrowsError(try header.set(UIImage.checkmark, forParameter: "image")) { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.invalidHeaderParameterValue)
        }

        XCTAssertNil(header.get(parameter: "data"))
        XCTAssertNil(header.get(parameter: "image"))
        XCTAssertFalse(String(data: header.data(), encoding: .utf8)!.contains("data"))
        XCTAssertFalse(String(data: header.data(), encoding: .utf8)!.contains("image"))

        XCTAssertEqual(header.get(parameter: "kid") as? String, "123")
        XCTAssertEqual(header.get(parameter: "string") as! String, "string")
        XCTAssertTrue(String(data: header.data(), encoding: .utf8)!.contains("string"))
        XCTAssertTrue(String(data: header.data(), encoding: .utf8)!.contains("kid"))
    }

    func testRemovingPublicPrivateParameters() throws {
        var header = JWSHeader(algorithm: .RS512)

        // setting parameters
        try header.set("123", forParameter: "kid")
        try header.set("string", forParameter: "string")

        XCTAssertEqual(header.get(parameter: "kid") as? String, "123")
        XCTAssertEqual(header.get(parameter: "string") as! String, "string")

        // and removing them
        header.remove(parameter: "kid")

        XCTAssertNil(header.get(parameter: "kid"))
        XCTAssertEqual(header.get(parameter: "string") as! String, "string")

        // but removing required parameters doesn't work
        XCTAssertNil(header.remove(parameter: "alg"))
        XCTAssertEqual(header.algorithm, .RS512)

        XCTAssertThrowsError(try header.set("boom", forParameter: "alg")) { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.invalidHeaderParameterValue)
        }
        XCTAssertThrowsError(try header.set(Optional<String>.none as Any, forParameter: "alg")) { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.invalidHeaderParameterValue)
        }
        XCTAssertEqual(header.algorithm, .RS512)
    }
}
// swiftlint:enable force_unwrapping
