// swiftlint:disable force_unwrapping
//
//  JWEPBES2Tests.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 11.12.23.
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

class JWEPBES2Tests: XCTestCase {
    func test() throws {
		var header = JWEHeader(keyManagementAlgorithm: .PBES2_HS256_A128KW, contentEncryptionAlgorithm: .A256CBCHS512)
        header.p2c = 1000
        let payload = Payload("Live long and prosper.".data(using: .utf8)!)
        let password = "123456"

        let encrypter = Encrypter(keyManagementAlgorithm: .PBES2_HS256_A128KW, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: password, pbes2SaltInputLength: 32)
        let jwe = try JWE(header: header, payload: payload, encrypter: encrypter!)
        let serialization = jwe.compactSerializedString

        let deserialization = try JWE(compactSerialization: serialization)
        let decrypter = Decrypter(keyManagementAlgorithm: .PBES2_HS256_A128KW, contentEncryptionAlgorithm: .A256CBCHS512, decryptionKey: password)
        let decrypted = try! deserialization.decrypt(using: decrypter!)

        XCTAssertEqual(payload.data(), decrypted.data())
        XCTAssertEqual(jwe.header.p2c, 1000)
        XCTAssertEqual(jwe.header.p2s?.count, 32)
    }
}
// swiftlint:enable force_unwrapping
