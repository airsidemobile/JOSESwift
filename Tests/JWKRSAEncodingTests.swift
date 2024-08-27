// swiftlint:disable force_unwrapping
//
//  JWKRSAEncodingTests.swift
//  Tests
//
//  Created by Daniel Egger on 05.02.18.
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

class JWKRSAEncodingTests: RSACryptoTestCase {

    func testPublicKeyEncoding() {
        let jwk = try! RSAPublicKey(publicKey: publicKeyAlice2048!, additionalParameters: [
            "alg": "RS256",
            "kid": "2011-04-29"
        ])

        let jsonData = try? JSONEncoder().encode(jwk)
        XCTAssertNotNil(jsonData!)

        let dict = try? JSONSerialization.jsonObject(with: jsonData!, options: []) as? [String: Any]
        XCTAssertNotNil(dict!)

        XCTAssertEqual(dict!["kty"] as? String ?? "", "RSA")
        XCTAssertEqual(dict!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(dict!["kid"] as? String ?? "", "2011-04-29")

        XCTAssertEqual(dict!["n"] as? String ?? "", expectedModulus2048Base64)
        XCTAssertEqual(dict!["e"] as? String ?? "", expectedExponentBase64)
    }

    func testEncodingPublicKeyWithUnregisteredParameter() {
        let jwk = try! RSAPublicKey(publicKey: publicKeyAlice2048!, additionalParameters: [
            "alg": "RS256",
            "kid": "2011-04-29",
            "breeze": "through"
        ])

        let jsonData = try? JSONEncoder().encode(jwk)
        XCTAssertNotNil(jsonData!)

        let dict = try? JSONSerialization.jsonObject(with: jsonData!, options: []) as? [String: Any]
        XCTAssertNotNil(dict!)

        XCTAssertEqual(dict!["kty"] as? String ?? "", "RSA")
        XCTAssertEqual(dict!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(dict!["kid"] as? String ?? "", "2011-04-29")
        XCTAssertNil(dict!["breeze"])

        XCTAssertEqual(dict!["n"] as? String ?? "", expectedModulus2048Base64)
        XCTAssertEqual(dict!["e"] as? String ?? "", expectedExponentBase64)
    }

    func testPrivateKeyEncoding() {
        let jwk = RSAPrivateKey(
            modulus: expectedModulus2048Base64,
            exponent: expectedExponentBase64,
            privateExponent: expectedPrivateExponentBase64,
            additionalParameters: [ "alg": "RS256", "kid": "2011-04-29" ]
        )

        let jsonData = try? JSONEncoder().encode(jwk)
        XCTAssertNotNil(jsonData!)

        let dict = try? JSONSerialization.jsonObject(with: jsonData!, options: []) as? [String: Any]
        XCTAssertNotNil(dict!)

        XCTAssertEqual(dict!["kty"] as? String ?? "", "RSA")
        XCTAssertEqual(dict!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(dict!["kid"] as? String ?? "", "2011-04-29")

        XCTAssertEqual(dict!["n"] as? String ?? "", expectedModulus2048Base64)
        XCTAssertEqual(dict!["e"] as? String ?? "", expectedExponentBase64)
        XCTAssertEqual(dict!["d"] as? String ?? "", expectedPrivateExponentBase64)
    }

    func testEncodingPrivateKeyWithUnregisteredParameter() {
        let jwk = RSAPrivateKey(
            modulus: expectedModulus2048Base64,
            exponent: expectedExponentBase64,
            privateExponent: expectedPrivateExponentBase64,
            additionalParameters: [ "alg": "RS256", "kid": "2011-04-29", "breeze": "through" ]
        )

        let jsonData = try? JSONEncoder().encode(jwk)
        XCTAssertNotNil(jsonData!)

        let dict = try? JSONSerialization.jsonObject(with: jsonData!, options: []) as? [String: Any]
        XCTAssertNotNil(dict!)

        XCTAssertEqual(dict!["kty"] as? String ?? "", "RSA")
        XCTAssertEqual(dict!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(dict!["kid"] as? String ?? "", "2011-04-29")
        XCTAssertNil(dict!["breeze"])

        XCTAssertEqual(dict!["n"] as? String ?? "", expectedModulus2048Base64)
        XCTAssertEqual(dict!["e"] as? String ?? "", expectedExponentBase64)
        XCTAssertEqual(dict!["d"] as? String ?? "", expectedPrivateExponentBase64)
    }

}
// swiftlint:enable force_unwrapping
