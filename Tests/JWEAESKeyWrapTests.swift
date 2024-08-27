//
//  JWEAESKeyWrapTests.swift
//  Tests
//
//  Created by Daniel Egger on 18.02.20.
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

// swiftlint:disable force_unwrapping

class JWEAESKeyWrapTests: XCTestCase {
    func testRoundtrip() throws {
        let symmetricKey = Data(base64URLEncoded: "GawgguFyGrWKav7AX4VKUg")!

        let header = JWEHeader(keyManagementAlgorithm: .A128KW, contentEncryptionAlgorithm: .A128CBCHS256)
        let payload = Payload("Live long and prosper.".data(using: .ascii)!)
        let encrypter = Encrypter(
            keyManagementAlgorithm: .A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256,
            encryptionKey: symmetricKey
        )!

        let jwe = try JWE(header: header, payload: payload, encrypter: encrypter)

        let decyrpter = Decrypter(
            keyManagementAlgorithm: .A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256,
            decryptionKey: symmetricKey
        )!

        let decryptedPayload = try jwe.decrypt(using: decyrpter)

        XCTAssertEqual(decryptedPayload.data(), payload.data())
    }

    func testRoundtripFailsWithWrongKey() throws {
        let symmetricKey = Data(base64URLEncoded: "GawgguFyGrWKav7AX4VKUg")!
        let wrongSymmetricKey = Data(base64URLEncoded: "WRONGuFyGrWKav7AX4VKUg")!

        let header = JWEHeader(keyManagementAlgorithm: .A128KW, contentEncryptionAlgorithm: .A128CBCHS256)
        let payload = Payload("Live long and prosper.".data(using: .ascii)!)
        let encrypter = Encrypter(
            keyManagementAlgorithm: .A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256,
            encryptionKey: symmetricKey
        )!

        let jwe = try JWE(header: header, payload: payload, encrypter: encrypter)

        let decyrpter = Decrypter(
            keyManagementAlgorithm: .A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256,
            decryptionKey: wrongSymmetricKey
        )!

        XCTAssertThrowsError(try jwe.decrypt(using: decyrpter))
    }
}
// swiftlint:enable force_unwrapping
