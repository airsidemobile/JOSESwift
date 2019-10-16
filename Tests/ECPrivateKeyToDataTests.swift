//
//  ECPrivateKeyToDataTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 10.01.2019.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
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

class ECPrivateKeyToDataTests: ECCryptoTestCase {

    func testPrivateKeyToData() {
        allTestData.forEach { testData in
            let jwk = try! ECPrivateKey(
                    crv: testData.expectedCurveType,
                    x: testData.expectedXCoordinateBase64Url,
                    y: testData.expectedYCoordinateBase64Url,
                    privateKey: testData.expectedPrivateBase64Url
            )
            let data = try! jwk.converted(to: Data.self)

            XCTAssertEqual(data, testData.privateKeyData)
        }
    }

}
