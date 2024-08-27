// swiftlint:disable force_unwrapping
//
//  ECPrivateKeyToSecKeyTests.swift
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

class ECPrivateKeyToSecKeyTests: ECCryptoTestCase {

    func testPrivateKeyToSecKey() {
        allTestData.forEach { testData in
            let jwk = try! ECPrivateKey(
                    crv: testData.expectedCurveType,
                    x: testData.expectedXCoordinateBase64Url,
                    y: testData.expectedYCoordinateBase64Url,
                    privateKey: testData.expectedPrivateBase64Url
            )
            let key = try! jwk.converted(to: SecKey.self)

            XCTAssertEqual(SecKeyCopyExternalRepresentation(key, nil)! as Data, testData.privateKeyData)
        }
    }

    func testInvalidPrivateKeyToSecKey() {
        allTestData.forEach { testData in
            let crv = testData.expectedCurveType
            let x = testData.expectedXCoordinateBase64Url
            let y = testData.expectedYCoordinateBase64Url
            let privateKey = testData.expectedPrivateBase64Url
            let invalid = "\u{96}"
            checkInvalidArgumentListForException(crv: "P-INVALID", x: x, y: y, privateKey: privateKey)
            checkInvalidArgumentListForException(crv: crv, x: invalid, y: y, privateKey: privateKey)
            checkInvalidArgumentListForException(crv: crv, x: x, y: invalid, privateKey: privateKey)
            checkInvalidArgumentListForException(crv: crv, x: x, y: y, privateKey: invalid)
        }
    }

    // MARK: Helper functions

    func checkInvalidArgumentListForException(crv: String, x: String, y: String, privateKey: String) {
        let closure = {
            let jwk = try ECPrivateKey(crv: crv, x: x, y: y, privateKey: privateKey)
            _ = try jwk.converted(to: SecKey.self)
        }
        XCTAssertThrowsError(try closure())
    }

}
// swiftlint:enable force_unwrapping
