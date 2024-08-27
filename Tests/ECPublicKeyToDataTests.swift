// swiftlint:disable force_unwrapping
//
//  ECPublicKeyToDataTests.swift
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

class ECPublicKeyToDataTests: ECCryptoTestCase {

    func testPublicKeyToData() {
        allTestData.forEach { testData in
            let jwk = ECPublicKey(
                    crv: ECCurveType(rawValue: testData.expectedCurveType)!,
                    x: testData.expectedXCoordinateBase64Url,
                    y: testData.expectedYCoordinateBase64Url)
            let data = try! jwk.converted(to: Data.self)

            XCTAssertEqual(data, testData.publicKeyData)
        }
    }

}
// swiftlint:enable force_unwrapping
