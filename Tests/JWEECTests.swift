//
//  JWEECTests.swift
//  Tests
//
//  Created by Mikael Rucinsky on 07.12.20.
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

class JWEECTests: ECCryptoTestCase {

    let pubJwk = """
      {
        "crv": "P-256",
        "kty": "EC",
        "x": "CQJxA68WhgU3hztigbedfLtJitDhScq3XSnXgO0FV5o",
        "y": "WFg6s36izURa733WqeoJ8zXMd7ho5OSwdWnMsEPgTEI"
      }
    """.data(using: .utf8)

    let privJwk = """
      {
        "crv": "P-256",
        "d": "920OCD0fW97YXbQNN-JaOtaDgbuNyVxXgKwjfXPPqv4",
        "kty": "EC",
        "x": "CQJxA68WhgU3hztigbedfLtJitDhScq3XSnXgO0FV5o",
        "y": "WFg6s36izURa733WqeoJ8zXMd7ho5OSwdWnMsEPgTEI"
      }
    """.data(using: .utf8)

    let plaintext = "Lorem Ipsum"

    func test() {

        guard let publicJWK = pubJwk, let publicKey = try? ECPublicKey(data: publicJWK) else {
            return XCTAssertThrowsError("publicKey is nil")
        }

        guard let privateJWK = privJwk, let privateKey = try? ECPrivateKey(data: privateJWK) else {
            return XCTAssertThrowsError("privateKey is nil")
        }

        guard let input = plaintext.data(using: .utf8),
              let encrypter = Encrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                        contentEncryptionAlgorithm: .A256CBCHS512,
                                        encryptionKey: publicKey),
              let decrypter = Decrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                        contentEncryptionAlgorithm: .A256CBCHS512,
                                        decryptionKey: privateKey) else {
            return XCTAssertThrowsError("wrong inputs")
        }

        let payload = Payload(input)
        let jwe = try! JWE(header: JWEHeader(keyManagementAlgorithm: .ECDH_ES_A128KW, contentEncryptionAlgorithm: .A256CBCHS512),
                           payload: payload,
                           encrypter: encrypter)
        let serialization = jwe.compactSerializedString

        let deserialization = try! JWE(compactSerialization: serialization)
        let decrypted = try! deserialization.decrypt(using: decrypter)
        XCTAssertEqual(input, decrypted.data())
    }

}
