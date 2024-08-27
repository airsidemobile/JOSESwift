//
//  DataECPublicKeyTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 27.10.18.
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

class DataECPublicKeyTests: ECCryptoTestCase {

    func testPublicKeyCoordinates() {
        allTestData.forEach { testData in
            let components = _getComponents(testData: testData)
            XCTAssertEqual(testData.expectedXCoordinate, components?.x)
            XCTAssertEqual(testData.expectedYCoordinate, components?.y)
        }
    }

    func testPublicKeyCurveType() {
        allTestData.forEach { testData in
            let components = _getComponents(testData: testData)
            XCTAssertEqual(testData.expectedCurveType, components?.crv)
        }
    }

    func testDataFromPublicKeyComponents() {
        allTestData.forEach { testData in
            let components = (testData.expectedCurveType, testData.expectedXCoordinate, testData.expectedYCoordinate)
            let data = try! Data.representing(ecPublicKeyComponents: components)
            XCTAssertEqual(data, testData.publicKeyData)
        }
    }

    func testCompressedPointRejection() {
        allTestData.forEach { testData in
            let errorHandler = { (error: Error) in
                switch error {
                case JOSESwiftError.compressedCurvePointsUnsupported: return
                default: XCTFail("Unexpected error: \(error)")
                }
            }
            checkInvalidDataToPublicKey(
                    compression: UInt8(0x03),
                    x: testData.expectedXCoordinate,
                    y: testData.expectedYCoordinate,
                    errorHandler: errorHandler
            )
        }
    }

    func testInvalidPointOctetLength() {
        allTestData.forEach { testData in
            let errorHandler = { (error: Error) in
                switch error {
                case JOSESwiftError.invalidCurvePointOctetLength: return
                default: XCTFail("Unexpected error: \(error)")
                }
            }
            checkInvalidDataToPublicKey(
                    compression: UInt8(0x04),
                    x: testData.expectedXCoordinate,
                    y: testData.expectedYCoordinate.dropLast(),
                    errorHandler: errorHandler
            )
        }
    }

    // MARK: Helper functions

    private func _getComponents(testData: ECTestKeyData) -> ECPublicKeyComponents? {
        guard let components = try? testData.publicKeyData.ecPublicKeyComponents() else {
            XCTFail("components = try? keyData.ecPublicKeyComponents()")
            return nil
        }
        return components
    }

    private func checkInvalidDataToPublicKey(compression: UInt8, x: Data, y: Data, errorHandler: (Error) -> Void) {
        let keyData = ECTestKeyData.createKeyData(compression: compression, x: x, y: y, privateKey: nil)
        XCTAssertThrowsError(
                try keyData.ecPublicKeyComponents(),
                "No error thrown for invalid point data"
        ) { error in errorHandler(error) }
    }

}
