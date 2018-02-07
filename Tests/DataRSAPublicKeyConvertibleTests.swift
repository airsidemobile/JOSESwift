//
//  DataRSAPublicKeyConvertibleTests.swift
//  Tests
//
//  Created by Daniel Egger on 07.02.18.
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
@testable import SwiftJOSE

class DataRSAPublicKeyConvertibleTests: XCTestCase {

    let publicKeyData = Data(base64Encoded: """
        MIIBCgKCAQEAiADzxMJ+l/NIVPbqz9eoBenUCCUiNNfZ37c6gUJwWEfJRyGchAe9\
        6m4GLr3pzj2A3Io4MSKf9dDWMak6qkR/XYljSjZBbXAhQan2sIB5qyPW7NJ7XpJW\
        HoaHdHwEN9Cj29zL+WtFk6lC1rPDmNPRTmRy0ct4EP4YJ49PMcoKJQKbog79ws1K\
        dDzNGTVVkEgLB4VOlW8A164kaK8+xMUxTqySUtigLTDUMqjQ/81SFgsNnMUqnxp8\
        7bKD77olYBia88r8V2YXEx1Jgl8t22gNNh6lkN8BDqlkb/Y2uS+c7vlYIfSH6WYk\
        VsSPsrA+GLLRo/R07FGxvs2M5gZxnmlvewIDAQAB
        """
    )!

    func testLeadingZeroDropped() {
        let (modulus, _) = try! publicKeyData.rsaPublicKeyComponents()

        XCTAssertEqual(try! [UInt8](publicKeyData).read(.sequence).read(.integer).first!, 0x00)
        XCTAssertNotEqual([UInt8](modulus).first!, 0x00)
    }
    
}
