//
//  JWKSetCodingTests.swift
//  Tests
//
//  Created by Daniel Egger on 15.02.18.
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

class JWKSetCodingTests: XCTestCase {

    // - MARK: Test data from the JWK RFC: https://tools.ietf.org/html/rfc7517#appendix-A.

    let modulus = """
        0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhD\
        R1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6C\
        f0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1\
        n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1\
        jF44-csFCur-kEgU8awapJzKnqDKgw
        """

    let exponent = """
        AQAB
        """

    let privateExponent = """
        X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5\
        fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRU\
        ohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx\
        4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbI\
        kfz0Y6mqnOYtqc0X4jfcKoAC8Q
        """

    let additionalParameters = [
        "kty": "RSA",
        "alg": "RS256",
        "kid": "2011-04-29"
    ]

    let testDataOneRSAPublicKey = """
        {"keys":[{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","n":"0vx7agoe\
        bGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_\
        BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-\
        65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD\
        08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-\
        kEgU8awapJzKnqDKgw"}]}
        """.data(using: .utf8)!

    let testDataTwoRSAPublicKeys = """
        {"keys":[{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","n":"0vx7agoe\
        bGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_\
        BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-\
        65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD\
        08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-\
        kEgU8awapJzKnqDKgw"},{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","\
        n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFx\
        uhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w\
        6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn\
        1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1\
        jF44-csFCur-kEgU8awapJzKnqDKgw"}]}
        """.data(using: .utf8)!

    let testDataRSAPublicAndPrivateKey = """
        {"keys":[{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","n":"0vx7agoe\
        bGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_\
        BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-\
        65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD\
        08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-\
        kEgU8awapJzKnqDKgw"},{"alg":"RS256","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3Ea\
        G6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijw\
        p3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6\
        TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z\
        4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q","e":"AQAB"\
        ,"kid":"2011-04-29","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFb\
        WhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ\
        _2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8\
        KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4l\
        Fd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}]}
        """.data(using: .utf8)!

    // - MARK: Encoding Tests

    func testEncodingOneRSAPublicKey() {
        let set: JWKSet = [
            RSAPublicKey(modulus: modulus, exponent: exponent, additionalParameters: additionalParameters)
        ]

        let encoder = JSONEncoder()

        // Sorting keys is needed to compare the encoding outcome with the already sorted test data.
        // Otherwise the encoding is correct but because the order of keys is not defined, the encoding outcome and
        // the test data can differ.
        if #available(iOS 11.0, *) {
            encoder.outputFormatting = .sortedKeys
        } else {
            XCTFail("Tests need to be executed on iOS11 or above to obatin sorted JSON keys for comparison.")
        }

        XCTAssertEqual(try! encoder.encode(set), testDataOneRSAPublicKey)
    }

    func testEncodingTwoRSAPublicKeys() {
        let set: JWKSet = [
            RSAPublicKey(modulus: modulus, exponent: exponent, additionalParameters: additionalParameters),
            RSAPublicKey(modulus: modulus, exponent: exponent, additionalParameters: additionalParameters)
        ]

        let encoder = JSONEncoder()

        // Sorting keys is needed to compare the encoding outcome with the already sorted test data.
        // Otherwise the encoding is correct but because the order of keys is not defined, the encoding outcome and
        // the test data can differ.
        if #available(iOS 11.0, *) {
            encoder.outputFormatting = .sortedKeys
        } else {
            XCTFail("Tests need to be executed on iOS11 or above to obatin sorted JSON keys for comparison.")
        }

        XCTAssertEqual(try! encoder.encode(set), testDataTwoRSAPublicKeys)
    }

    func testEncodingRSAPublicAndPrivateKey() {
        let set: JWKSet = [
            RSAPublicKey(modulus: modulus, exponent: exponent, additionalParameters: additionalParameters),
            RSAPrivateKey(modulus: modulus, exponent: exponent, privateExponent: privateExponent, additionalParameters: additionalParameters)
        ]

        let encoder = JSONEncoder()

        // Sorting keys is needed to compare the encoding outcome with the already sorted test data.
        // Otherwise the encoding is correct but because the order of keys is not defined, the encoding outcome and
        // the test data can differ.
        if #available(iOS 11.0, *) {
            encoder.outputFormatting = .sortedKeys
        } else {
            XCTFail("Tests need to be executed on iOS11 or above to obatin sorted JSON keys for comparison.")
        }

        XCTAssertEqual(try! encoder.encode(set), testDataRSAPublicAndPrivateKey)
    }

    // - MARK: Decoding Tests

    func testDecodingOneRSAPublicKey() {
        let jwkSet = try! JSONDecoder().decode(JWKSet.self, from: testDataOneRSAPublicKey)

        XCTAssertEqual(jwkSet.keys.count, 1)

        XCTAssert(jwkSet[0] is RSAPublicKey)

        let rsaKey = jwkSet[0] as! RSAPublicKey

        XCTAssertEqual(rsaKey.modulus, modulus)
        XCTAssertEqual(rsaKey.exponent, exponent)
        XCTAssertEqual(rsaKey["kty"], additionalParameters["kty"])
        XCTAssertEqual(rsaKey["kid"], additionalParameters["kid"])
        XCTAssertEqual(rsaKey["alg"], additionalParameters["alg"])
    }

    func testDecodingTwoRSAPublicKeys() {
        let jwkSet = try! JSONDecoder().decode(JWKSet.self, from: testDataTwoRSAPublicKeys)

        XCTAssertEqual(jwkSet.keys.count, 2)

        XCTAssert(jwkSet[0] is RSAPublicKey)

        var rsaKey = jwkSet[0] as! RSAPublicKey

        XCTAssertEqual(rsaKey.modulus, modulus)
        XCTAssertEqual(rsaKey.exponent, exponent)
        XCTAssertEqual(rsaKey["kty"], additionalParameters["kty"])
        XCTAssertEqual(rsaKey["kid"], additionalParameters["kid"])
        XCTAssertEqual(rsaKey["alg"], additionalParameters["alg"])

        XCTAssert(jwkSet[1] is RSAPublicKey)

        rsaKey = jwkSet[1] as! RSAPublicKey

        XCTAssertEqual(rsaKey.modulus, modulus)
        XCTAssertEqual(rsaKey.exponent, exponent)
        XCTAssertEqual(rsaKey["kty"], additionalParameters["kty"])
        XCTAssertEqual(rsaKey["kid"], additionalParameters["kid"])
        XCTAssertEqual(rsaKey["alg"], additionalParameters["alg"])
    }

    func testDecodingRSAPublicAndPrivateKey() {
        let jwkSet = try! JSONDecoder().decode(JWKSet.self, from: testDataRSAPublicAndPrivateKey)

        XCTAssertEqual(jwkSet.keys.count, 2)

        XCTAssert(jwkSet[0] is RSAPublicKey)

        let rsaPublicKey = jwkSet[0] as! RSAPublicKey

        XCTAssertEqual(rsaPublicKey.modulus, modulus)
        XCTAssertEqual(rsaPublicKey.exponent, exponent)
        XCTAssertEqual(rsaPublicKey["kty"], additionalParameters["kty"])
        XCTAssertEqual(rsaPublicKey["kid"], additionalParameters["kid"])
        XCTAssertEqual(rsaPublicKey["alg"], additionalParameters["alg"])

        XCTAssert(jwkSet[1] is RSAPrivateKey)

        let rsaPrivateKey = jwkSet[1] as! RSAPrivateKey

        XCTAssertEqual(rsaPrivateKey.modulus, modulus)
        XCTAssertEqual(rsaPrivateKey.exponent, exponent)
        XCTAssertEqual(rsaPrivateKey.privateExponent, privateExponent)
        XCTAssertEqual(rsaPrivateKey["kty"], additionalParameters["kty"])
        XCTAssertEqual(rsaPrivateKey["kid"], additionalParameters["kid"])
        XCTAssertEqual(rsaPrivateKey["alg"], additionalParameters["alg"])
    }

    // - MARK: Convenience Helpers Test

    func testInitWithData() {
        let jwkSet = try! JWKSet(data: testDataTwoRSAPublicKeys)

        XCTAssertEqual(jwkSet.keys.count, 2)

        XCTAssert(jwkSet[0] is RSAPublicKey)

        var rsaKey = jwkSet[0] as! RSAPublicKey

        XCTAssertEqual(rsaKey.modulus, modulus)
        XCTAssertEqual(rsaKey.exponent, exponent)
        XCTAssertEqual(rsaKey["kty"], additionalParameters["kty"])
        XCTAssertEqual(rsaKey["kid"], additionalParameters["kid"])
        XCTAssertEqual(rsaKey["alg"], additionalParameters["alg"])

        XCTAssert(jwkSet[1] is RSAPublicKey)

        rsaKey = jwkSet[1] as! RSAPublicKey

        XCTAssertEqual(rsaKey.modulus, modulus)
        XCTAssertEqual(rsaKey.exponent, exponent)
        XCTAssertEqual(rsaKey["kty"], additionalParameters["kty"])
        XCTAssertEqual(rsaKey["kid"], additionalParameters["kid"])
        XCTAssertEqual(rsaKey["alg"], additionalParameters["alg"])
    }

    func testToJsonData() {
        let jwkSet = try! JWKSet(data: testDataTwoRSAPublicKeys)

        // Only test count because the ordering of the keys might be different.
        // The actual encoding is tested above with an ordered keys encoder.
        XCTAssertEqual(jwkSet.jsonData()!.count, testDataTwoRSAPublicKeys.count)
    }

    func testToJsonString() {
        let jwkSet = try! JWKSet(data: testDataTwoRSAPublicKeys)

        // Only test count because the ordering of the keys might be different.
        // The actual encoding is tested above with an ordered keys encoder.
        XCTAssertEqual(jwkSet.jsonString()!.count, String(data: testDataTwoRSAPublicKeys, encoding: .utf8)!.count)
    }
}
