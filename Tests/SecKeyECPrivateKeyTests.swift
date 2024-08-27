// swiftlint:disable force_unwrapping
//
//  SecKeyECPrivateKeyTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 10.01.2019.
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

class SecKeyECPrivateKeyTests: ECCryptoTestCase {

    func testPrivateKeyComponents() {
        allTestData.forEach { testData in
            let components = try? testData.privateKey.ecPrivateKeyComponents()
            XCTAssertNotNil(components)
            XCTAssertEqual(components?.crv, testData.expectedCurveType)
            XCTAssertEqual(components?.x, testData.expectedXCoordinate)
            XCTAssertEqual(components?.y, testData.expectedYCoordinate)
            XCTAssertEqual(components?.d, testData.expectedPrivateOctetString)
        }
    }

    func testPublicKeyToPrivateComponents() {
        XCTAssertThrowsError(try p256.publicKey.ecPrivateKeyComponents()) { error in
            XCTAssertEqual(error as? JWKError, JWKError.notAPrivateKey)
        }
    }

    func testJWKFromPrivateKey() {
        allTestData.forEach { testData in
            let jwk = try? ECPrivateKey(privateKey: testData.privateKey)

            XCTAssertNotNil(jwk)
            XCTAssertEqual(jwk?.crv.rawValue, testData.expectedCurveType)
            XCTAssertEqual(jwk?.x, testData.expectedXCoordinateBase64Url)
            XCTAssertEqual(jwk?.y, testData.expectedYCoordinateBase64Url)
            XCTAssertEqual(jwk?.privateKey, testData.expectedPrivateBase64Url)
        }
    }

    func testPrivateKeyFromPrivateComponents() throws {
        try allTestData.forEach { testData in
            let components = (
                    testData.expectedCurveType,
                    testData.expectedXCoordinate,
                    testData.expectedYCoordinate,
                    testData.expectedPrivateOctetString
            )
            let secKey = try SecKey.representing(ecPrivateKeyComponents: components)

            let data = SecKeyCopyExternalRepresentation(secKey, nil)! as Data
            let dataExpected = SecKeyCopyExternalRepresentation(testData.privateKey, nil)! as Data

            XCTAssertEqual(data, dataExpected)
        }
    }

    func testPrivateKeyFromInvalidCurveType() {
        let components = ("P-Invalid", p256.expectedXCoordinate, p256.expectedYCoordinate, p256.expectedPrivateOctetString)
        XCTAssertThrowsError(try SecKey.representing(ecPrivateKeyComponents: components)) { error in
            XCTAssertEqual(error as? JWKError, JWKError.invalidECCurveType)
        }
    }
}
// swiftlint:enable force_unwrapping
