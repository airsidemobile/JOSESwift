//
//  SecKeyECPublicKeyTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 27.10.18.
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

class SecKeyECPublicKeyTests: ECCryptoTestCase {

    private func _testPublicKeyComponents(testData: ECTestKeyData) {
        let components = try? testData.publicKey.ecPublicKeyComponents()
        XCTAssertNotNil(components)
        XCTAssertEqual(components?.crv, testData.expectedCurveType)
        XCTAssertEqual(components?.x, testData.expectedXCoordinate)
        XCTAssertEqual(components?.y, testData.expectedYCoordinate)
    }

    func testPublicKeyComponents() {
        [p256, p384, p521].forEach { testData in
            _testPublicKeyComponents(testData: testData)
        }
    }

    func testPrivateKeyToPublicComponents() {
        XCTAssertThrowsError(try p256.privateKey.ecPublicKeyComponents()) { error in
            XCTAssertEqual(error as? JWKError, JWKError.notAPublicKey)
        }
    }

    private func _testJWKFromPublicKey(testData: ECTestKeyData) {
        let jwk = try? ECPublicKey(publicKey: testData.publicKey)

        XCTAssertNotNil(jwk)
        XCTAssertEqual(jwk?.crv.rawValue, testData.expectedCurveType)
        XCTAssertEqual(jwk?.x, testData.expectedXCoordinateBase64Url)
        XCTAssertEqual(jwk?.y, testData.expectedYCoordinateBase64Url)
    }

    func testJWKFromPublicKey() {
        [p256, p384, p521].forEach { testData in
            _testJWKFromPublicKey(testData: testData)
        }
    }

    private func _testPublicKeyFromPublicComponents(testData: ECTestKeyData) {
        let components = (testData.expectedCurveType, testData.expectedXCoordinate, testData.expectedYCoordinate)
        guard let secKey = try? SecKey.representing(ecPublicKeyComponents: components) else {
            XCTFail()
            return
        }

        let data = SecKeyCopyExternalRepresentation(secKey, nil)! as Data
        let dataExpected = SecKeyCopyExternalRepresentation(testData.publicKey, nil)! as Data

        XCTAssertEqual(data, dataExpected)
    }

    func testPublicKeyFromPublicComponents() {
        [p256, p384, p521].forEach { testData in
            _testPublicKeyFromPublicComponents(testData: testData)
        }
    }

}
