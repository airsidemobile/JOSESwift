//
//  DataECPublicKeyTests.swift
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

class DataECPublicKeyTests: ECCryptoTestCase {

    private func _testPublicKeyCoordinates(testData: ECTestKeyData) {
        let components = _getComponents(testData: testData)
        XCTAssertEqual(testData.expectedXCoordinate, components?.x)
        XCTAssertEqual(testData.expectedYCoordinate, components?.y)
    }

    private func _testPublicKeyCurveType(testData: ECTestKeyData) {
        let components = _getComponents(testData: testData)
        XCTAssertEqual(testData.expectedCurveType, components?.crv)
    }

    private func _testDataFromPublicKeyComponents(testData: ECTestKeyData) {
        let components = (testData.expectedCurveType, testData.expectedXCoordinate, testData.expectedYCoordinate)
        let data = try! Data.representing(ecPublicKeyComponents: components)
        XCTAssertEqual(data, testData.publicKeyData)
    }

    func testPublicKeyCoordinates() {
        [p256, p384, p521].forEach { testData in
            _testPublicKeyCoordinates(testData: testData)
        }
    }

    func testPublicKeyCurveType() {
        [p256, p384, p521].forEach { testData in
            _testPublicKeyCurveType(testData: testData)
        }
    }

    func testDataFromPublicKeyComponents() {
        [p256, p384, p521].forEach { testData in
            _testDataFromPublicKeyComponents(testData: testData)
        }
    }

    private func _getComponents(testData: ECTestKeyData) -> ECPublicKeyComponents? {
        guard let components = try? testData.publicKeyData.ecPublicKeyComponents() else {
            XCTFail("components = try? keyData.ecPublicKeyComponents()")
            return nil
        }
        return components
    }

}
