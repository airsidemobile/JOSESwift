// swiftlint:disable force_unwrapping
//
//  EncrypterDecrypterInitializationTests.swift
//  Tests
//
//  Created by Daniel Egger on 17.07.18.
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

// https://stackoverflow.com/a/38725560/5233456
private func ~= <T: Equatable>(array: [T], value: T) -> Bool {
    return array.contains(value)
}

class EncrypterDecrypterInitializationTests: RSACryptoTestCase {
    let rsaKeyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.RSA1_5, .RSAOAEP, .RSAOAEP256]
    let aesKeyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.A128KW, .A192KW, .A256KW]
    let ecdhKeyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.ECDH_ES, .ECDH_ES_A128KW, .ECDH_ES_A192KW, .ECDH_ES_A256KW]

    @available(*, deprecated)
    func testEncrypterDeprecated1Initialization() {
        for algorithm in rsaKeyManagementModeAlgorithms {
            XCTAssertNotNil(
                Encrypter(
                    keyEncryptionAlgorithm: algorithm,
                    keyEncryptionKey: publicKeyAlice2048!,
                    contentEncyptionAlgorithm: .A256CBCHS512
                )
            )
        }
    }

    @available(*, deprecated)
    func testEncrypterDeprecated2Initialization() {
        for algorithm in rsaKeyManagementModeAlgorithms {
            XCTAssertNotNil(
                Encrypter(
                    keyEncryptionAlgorithm: algorithm,
                    encryptionKey: publicKeyAlice2048!,
                    contentEncyptionAlgorithm: .A256CBCHS512
                )
            )
        }
    }

    func testSuccessfulEncrypterInitialization() {
        for algorithm in KeyManagementAlgorithm.allCases {
            switch algorithm {
            case rsaKeyManagementModeAlgorithms:
                XCTAssertNotNil(
                    Encrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        encryptionKey: publicKeyAlice2048!
                    )
                )
            case aesKeyManagementModeAlgorithms:
                XCTAssertNotNil(
                    Encrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        encryptionKey: Data()
                    )
                )
            case .direct:
                XCTAssertNotNil(
                    Encrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        encryptionKey: Data()
                    )
                )
            case ecdhKeyManagementModeAlgorithms:
                let pubJwk = """
                  {
                    "crv": "P-256",
                    "kty": "EC",
                    "x": "CQJxA68WhgU3hztigbedfLtJitDhScq3XSnXgO0FV5o",
                    "y": "WFg6s36izURa733WqeoJ8zXMd7ho5OSwdWnMsEPgTEI"
                  }
                """.data(using: .utf8)

                guard let publicJWK = pubJwk, let publicKey = try? ECPublicKey(data: publicJWK) else {
                    return XCTAssertThrowsError("publicKey is nil")
                }

                XCTAssertNotNil(
                    Encrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A256CBCHS512,
                        encryptionKey: publicKey
                    )
                )
            default:
                XCTFail()
            }
        }
    }

    func testWrongKeyTypeEncrypterInitialization() {
        for algorithm in KeyManagementAlgorithm.allCases {
            switch algorithm {
            case rsaKeyManagementModeAlgorithms:
                XCTAssertNil(
                    Encrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        encryptionKey: Data()
                    )
                )
            case aesKeyManagementModeAlgorithms:
                XCTAssertNil(
                    Encrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        encryptionKey: publicKeyAlice2048!
                    )
                )
            case .direct:
                XCTAssertNil(
                    Encrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        encryptionKey: publicKeyAlice2048!
                    )
                )
            case ecdhKeyManagementModeAlgorithms:
                XCTAssertNil(
                    Encrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A256CBCHS512,
                        encryptionKey: Data()
                    )
                )
            default:
                XCTFail()
            }
        }
    }

    @available(*, deprecated)
    func testDecrypterDeprecated1Initialization() {
        for algorithm in rsaKeyManagementModeAlgorithms {
            XCTAssertNotNil(
                Decrypter(
                    keyDecryptionAlgorithm: algorithm,
                    keyDecryptionKey: privateKeyAlice2048!,
                    contentDecryptionAlgorithm: .A256CBCHS512
                )
            )
        }
    }

    @available(*, deprecated)
    func testDecrypterDeprecated2Initialization() {
        for algorithm in rsaKeyManagementModeAlgorithms {
            XCTAssertNotNil(
                Decrypter(
                    keyDecryptionAlgorithm: algorithm,
                    decryptionKey: privateKeyAlice2048!,
                    contentDecryptionAlgorithm: .A256CBCHS512
                )
            )
        }
    }

    func testDecrypterEncrypterInitialization() {
        for algorithm in KeyManagementAlgorithm.allCases {
            switch algorithm {
            case rsaKeyManagementModeAlgorithms:
                XCTAssertNotNil(
                    Decrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        decryptionKey: publicKeyAlice2048!
                    )
                )
            case aesKeyManagementModeAlgorithms:
                XCTAssertNotNil(
                    Decrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        decryptionKey: Data()
                    )
                )
            case .direct:
                XCTAssertNotNil(
                    Decrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        decryptionKey: Data()
                    )
                )
            case ecdhKeyManagementModeAlgorithms:
                let privJwk = """
                  {
                    "crv": "P-256",
                    "d": "920OCD0fW97YXbQNN-JaOtaDgbuNyVxXgKwjfXPPqv4",
                    "kty": "EC",
                    "x": "CQJxA68WhgU3hztigbedfLtJitDhScq3XSnXgO0FV5o",
                    "y": "WFg6s36izURa733WqeoJ8zXMd7ho5OSwdWnMsEPgTEI"
                  }
                """.data(using: .utf8)

                guard let privateJWK = privJwk, let privateKey = try? ECPrivateKey(data: privateJWK) else {
                    return XCTAssertThrowsError("privateKey is nil")
                }

                XCTAssertNotNil(
                    Decrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A256CBCHS512,
                        decryptionKey: privateKey
                    )
                )
            default:
                XCTFail()
            }
        }
    }

    func testWrongKeyTypeDecrypterInitialization() {
        for algorithm in KeyManagementAlgorithm.allCases {
            switch algorithm {
            case rsaKeyManagementModeAlgorithms:
                XCTAssertNil(
                    Decrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        decryptionKey: Data()
                    )
                )
            case aesKeyManagementModeAlgorithms:
                XCTAssertNil(
                    Decrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        decryptionKey: publicKeyAlice2048!
                    )
                )
            case .direct:
                XCTAssertNil(
                    Decrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        decryptionKey: publicKeyAlice2048!
                    )
                )
            case ecdhKeyManagementModeAlgorithms:
                XCTAssertNil(
                    Decrypter(
                        keyManagementAlgorithm: algorithm,
                        contentEncryptionAlgorithm: .A128CBCHS256,
                        decryptionKey: Data()
                    )
                )
            default:
                XCTFail()
            }
        }
    }
}
// swiftlint:enable force_unwrapping
