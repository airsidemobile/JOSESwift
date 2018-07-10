//
//  SymmetricKeyTests.swift
//  Tests
//
//  Created by Daniel Egger on 10.07.18.
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


class SymmetricKeyTests: XCTestCase {
    
    func testCreatingAndParsingSymetricKey() {

        // Example key data from https://tools.ietf.org/html/rfc7517#appendix-A.3 but with different "alg" parameter
        // because we don't (yet) support "A128KW".

        let key = Data(bytes: [ 0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5, 0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52 ])

        let createdJWK = SymmetricKey(key: key, additionalParameters: [ "alg": SymmetricKeyAlgorithm.A256CBCHS512.rawValue ])

        XCTAssertEqual("{\"kty\":\"oct\",\"alg\":\"A256CBC-HS512\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}", createdJWK.jsonString()!)

        let json = createdJWK.jsonData()!

        let parsedJWK = try! SymmetricKey(data: json)

        let keyData = try! parsedJWK.converted(to: Data.self)

        XCTAssertEqual(keyData, key)

    }
    
}
