// swiftlint:disable force_unwrapping
//
//  JWKECEncodingTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 09.01.2019.
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

class JWKECEncodingTests: ECCryptoTestCase {

    private struct Consts {
        static let kid = "2018-TEST"
    }

    func testPublicKeyEncoding() {
        allTestData.forEach { keyData in
            let jwk = try! ECPublicKey(publicKey: keyData.publicKey, additionalParameters: [
                "alg": keyData.signatureAlgorithm,
                "kid": Consts.kid
            ])

            let jsonData = try? JSONEncoder().encode(jwk)
            let dict = checkAndGetDictionary(jsonData: jsonData)

            checkRegularParameters(dict: dict, keyData: keyData)
        }
    }

    func testEncodingPublicKeyWithUnregisteredParameter() {
        allTestData.forEach { keyData in
            let jwk = try! ECPublicKey(publicKey: keyData.publicKey, additionalParameters: [
                "alg": keyData.signatureAlgorithm,
                "kid": Consts.kid,
                "breeze": "through"
            ])

            let jsonData = try? JSONEncoder().encode(jwk)
            let dict = checkAndGetDictionary(jsonData: jsonData)

            checkRegularParameters(dict: dict, keyData: keyData)
            XCTAssertNil(dict["breeze"])
        }
    }

    func testPrivateKeyEncoding() {
        allTestData.forEach { keyData in
            let jwk = try! ECPrivateKey(
                    crv: keyData.expectedCurveType,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url,
                    privateKey: keyData.expectedPrivateBase64Url,
                    additionalParameters: ["alg": keyData.signatureAlgorithm, "kid": Consts.kid]
            )

            let jsonData = try? JSONEncoder().encode(jwk)
            let dict = checkAndGetDictionary(jsonData: jsonData)

            checkRegularParameters(dict: dict, keyData: keyData)
            XCTAssertEqual(dict["d"] as? String ?? "", keyData.expectedPrivateBase64Url)
        }
    }

    func testEncodingPrivateKeyWithUnregisteredParameter() {
        allTestData.forEach { keyData in
            let jwk = try! ECPrivateKey(
                    crv: keyData.expectedCurveType,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url,
                    privateKey: keyData.expectedPrivateBase64Url,
                    additionalParameters: ["alg": keyData.signatureAlgorithm, "kid": Consts.kid, "breeze": "through"]
            )

            let jsonData = try? JSONEncoder().encode(jwk)
            let dict = checkAndGetDictionary(jsonData: jsonData)

            checkRegularParameters(dict: dict, keyData: keyData)
            XCTAssertEqual(dict["d"] as? String ?? "", keyData.expectedPrivateBase64Url)
            XCTAssertNil(dict["breeze"])
        }
    }

    // MARK: Helper functions

    private func checkAndGetDictionary(jsonData: Data?) -> [String: Any] {
        XCTAssertNotNil(jsonData!)

        let dict = try? JSONSerialization.jsonObject(with: jsonData!, options: []) as? [String: Any]
        XCTAssertNotNil(dict!)
        return dict!
    }

    private func checkRegularParameters(dict: [String: Any], keyData: ECTestKeyData) {
        XCTAssertEqual(dict["kty"] as? String ?? "", "EC")
        XCTAssertEqual(dict["alg"] as? String ?? "", keyData.signatureAlgorithm)
        XCTAssertEqual(dict["kid"] as? String ?? "", Consts.kid)

        XCTAssertEqual(dict["x"] as? String ?? "", keyData.expectedXCoordinateBase64Url)
        XCTAssertEqual(dict["y"] as? String ?? "", keyData.expectedYCoordinateBase64Url)
    }
}
// swiftlint:enable force_unwrapping
