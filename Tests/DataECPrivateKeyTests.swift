//
//  DataECPrivateKeyTests.swift
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

class DataECPrivateKeyTests: ECCryptoTestCase {

    func testPrivateKeyCoordinates() {
        allTestData.forEach { testData in
            let components = _getComponents(testData: testData)
            XCTAssertEqual(testData.expectedXCoordinate, components?.x)
            XCTAssertEqual(testData.expectedYCoordinate, components?.y)
            XCTAssertEqual(testData.expectedPrivateOctetString, components?.d)
        }
    }

    func testPrivateKeyCurveType() {
        allTestData.forEach { testData in
            let components = _getComponents(testData: testData)
            XCTAssertEqual(testData.expectedCurveType, components?.crv)
        }
    }

    func testDataFromPrivateKeyComponents() {
        allTestData.forEach { testData in
            let components = (
                    testData.expectedCurveType,
                    testData.expectedXCoordinate,
                    testData.expectedYCoordinate,
                    testData.expectedPrivateOctetString
            )
            let data = try! Data.representing(ecPrivateKeyComponents: components)
            XCTAssertEqual(data, testData.privateKeyData)
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
            checkInvalidDataToPrivateKey(
                    compression: UInt8(0x03),
                    x: testData.expectedXCoordinate,
                    y: testData.expectedYCoordinate,
                    d: testData.expectedPrivateOctetString,
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
            checkInvalidDataToPrivateKey(
                    compression: UInt8(0x04),
                    x: testData.expectedXCoordinate,
                    y: testData.expectedYCoordinate,
                    d: testData.expectedPrivateOctetString.dropLast(),
                    errorHandler: errorHandler
            )
        }
    }

    func testInvalidComponentsToData() {
        let errorHandler = { (error: Error) in
            switch error {
            case JOSESwiftError.invalidCurvePointOctetLength: return
            default: XCTFail("Unexpected error: \(error)")
            }
        }
        let components = (
                p256.expectedCurveType,
                p256.expectedXCoordinate,
                p256.expectedYCoordinate,
                p256.expectedPrivateOctetString.dropLast()
        )
        XCTAssertThrowsError(
                try Data.representing(ecPrivateKeyComponents: components),
                "No error thrown for invalid point data"
        ) { error in errorHandler(error) }
    }

    // MARK: Helper functions

    private func _getComponents(testData: ECTestKeyData) -> ECPrivateKeyComponents? {
        guard let components = try? testData.privateKeyData.ecPrivateKeyComponents() else {
            XCTFail("components = try? keyData.ecPrivateKeyComponents()")
            return nil
        }
        return components
    }

    private func checkInvalidDataToPrivateKey(
            compression: UInt8,
            x: Data,
            y: Data,
            d: Data,
            errorHandler: (Error) -> Void
    ) {
        let keyData = ECTestKeyData.createKeyData(compression: compression, x: x, y: y, privateKey: d)
        XCTAssertThrowsError(
                try keyData.ecPrivateKeyComponents(),
                "No error thrown for invalid point data"
        ) { error in errorHandler(error) }
    }

}
