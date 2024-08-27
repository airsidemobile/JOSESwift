// swiftlint:disable force_unwrapping
//
//  JWSCustomEncrypterDecrypterTests.swift
//  Tests
//
//  Created by Daniel Egger on 22.02.18.
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

class JWSCustomEncrypterDecrypterTests: XCTestCase {
    private struct NoOpEncryptionKeyManagementMode: EncryptionKeyManagementMode {
        var algorithm: KeyManagementAlgorithm = .direct

        func determineContentEncryptionKey(with _: JOSESwift.JWEHeader) throws -> EncryptionKeyManagementModeContext {
            return .init(contentEncryptionKey: Data(), encryptedKey: Data(), jweHeader: nil)
        }
    }

    private struct NoOpContentEncrypter: ContentEncrypter {
        var algorithm: ContentEncryptionAlgorithm = .A128CBCHS256

        func encrypt(headerData: Data, payload: Payload, contentEncryptionKey: Data) throws -> ContentEncryptionContext {
            return .init(ciphertext: Data(), authenticationTag: Data(), initializationVector: Data())
        }
    }

    private struct NoOpDecryptionKeyManagementMode: DecryptionKeyManagementMode {
        var algorithm: KeyManagementAlgorithm = .direct

        func determineContentEncryptionKey(from encryptedKey: Data, with header: JOSESwift.JWEHeader) throws -> Data {
            return Data()
        }
    }

    private struct NoOpContentDecrypter: ContentDecrypter {
        var algorithm: ContentEncryptionAlgorithm = .A128CBCHS256

        func decrypt(decryptionContext: JOSESwift.ContentDecryptionContext) throws -> Data {
            return Data()
        }
    }

    func testCustomEncryption() throws {
        let header = JWEHeader(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A128CBCHS256)
        let payload = Payload("Summer, Sun, Cactus".data(using: .utf8)!)
        let customKeyManagementMode = NoOpEncryptionKeyManagementMode()
        let customContentEncrypter = NoOpContentEncrypter()
        let customEncrypter = Encrypter(
            customKeyManagementMode: customKeyManagementMode,
            customContentEncrypter: customContentEncrypter
        )

        let jwe = try JWE(header: header, payload: payload, encrypter: customEncrypter)

        XCTAssertEqual(jwe.ciphertext, Data())
        XCTAssertEqual(jwe.authenticationTag, Data())
        XCTAssertEqual(jwe.initializationVector, Data())
        XCTAssertEqual(jwe.encryptedKey, Data())
        XCTAssertEqual(jwe.header.keyManagementAlgorithm, .direct)
        XCTAssertEqual(jwe.header.contentEncryptionAlgorithm, .A128CBCHS256)
    }

    func testCustomDecryption() throws {
        let header = JWEHeader(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A128CBCHS256)
        let payload = Payload("Summer, Sun, Cactus".data(using: .utf8)!)

        let customEncyptionKeyManagementMode = NoOpEncryptionKeyManagementMode()
        let customContentEncrypter = NoOpContentEncrypter()
        let customEncrypter = Encrypter(
            customKeyManagementMode: customEncyptionKeyManagementMode,
            customContentEncrypter: customContentEncrypter
        )

        let testDummyKey = "not-so-secret".data(using: .utf8)!
        let joseDecrypter = Decrypter(
            keyManagementAlgorithm: .direct,
            contentEncryptionAlgorithm: .A128CBCHS256,
            decryptionKey: testDummyKey
        )!

        let customDecryptionKeyManagementMode = NoOpDecryptionKeyManagementMode()
        let customContentDecrypter = NoOpContentDecrypter()
        let customDecrypter = Decrypter(
            customKeyManagementMode: customDecryptionKeyManagementMode,
            customContentDecrypter: customContentDecrypter
        )

        let jwe = try JWE(header: header, payload: payload, encrypter: customEncrypter)

        let customDecryptedPayload = try jwe.decrypt(using: customDecrypter)

        XCTAssertEqual(customDecryptedPayload.data(), Data())
        XCTAssertEqual(jwe.header.keyManagementAlgorithm, .direct)
        XCTAssertEqual(jwe.header.contentEncryptionAlgorithm, .A128CBCHS256)

        XCTAssertThrowsError(try jwe.decrypt(using: joseDecrypter)) { (error: Error) in
            XCTAssertEqual(error as! JOSESwiftError, .decryptingFailed(description: "The operation couldn’t be completed. (JOSESwift.JWEError error 2.)"))
        }
    }
}
// swiftlint:enable force_unwrapping
