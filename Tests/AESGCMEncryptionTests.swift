// swiftlint:disable force_unwrapping
//
//  AESGCMEncryptionTests.swift
//  Tests
//
//  Created by Tobias Hagemann on 12.08.22.
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
import CryptoKit

@testable import JOSESwift

class AESGCMEncryptionTests: XCTestCase {
    // Common test data as per [RFC-7516](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1).
    let contentEncryptionKey256 = Data([
        177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
        212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
        234, 64, 252
    ])

    let expectedPlaintext = Data([
        84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
        111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
        101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
        101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
        110, 97, 116, 105, 111, 110, 46
    ])

    let ciphertext = Data([
        229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
        233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
        104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
        123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
        160, 109, 64, 63, 192
    ])

    let additionalAuthenticatedData = Data([
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
        116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
        54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81
    ])

    let initializationVector = Data([
        227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219
    ])

    let expectedCiphertext = Data([
        229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
        233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
        104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
        123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
        160, 109, 64, 63, 192
    ])

    let authenticationTag = Data([
        92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
        210, 145
    ])

    /// Tests the `AES` encryption implementation for A256GCM with the test data provided in the [RFC-7516](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1).
    func testEncryptingA256GCM() throws {
        let encrypter = AESGCMEncryption(contentEncryptionAlgorithm: .A256GCM)
        let symmetricEncryptionContext = try encrypter.encrypt(expectedPlaintext, initializationVector: initializationVector, additionalAuthenticatedData: additionalAuthenticatedData, contentEncryptionKey: contentEncryptionKey256)
        XCTAssertEqual(expectedCiphertext, symmetricEncryptionContext.ciphertext)
        XCTAssertEqual(authenticationTag, symmetricEncryptionContext.authenticationTag)
    }

    /// Tests the `AES` decryption implementation for A256GCM with the test data provided in the [RFC-7516](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1).
    func testDecryptingA256GCM() throws {
        let decrypter = AESGCMEncryption(contentEncryptionAlgorithm: .A256GCM)
        let plaintext = try decrypter.decrypt(ciphertext, initializationVector: initializationVector, additionalAuthenticatedData: additionalAuthenticatedData, authenticationTag: authenticationTag, contentEncryptionKey: contentEncryptionKey256)
        XCTAssertEqual(expectedPlaintext, plaintext)
    }

    /// Tests the `AES` decryption implementation for A256GCM with the test data provided in the [RFC-7516](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1).
    func testDecryptingA256GCMUsingDecryptionContext() throws {
        let context = ContentDecryptionContext(
            ciphertext: ciphertext,
            initializationVector: initializationVector,
            additionalAuthenticatedData: additionalAuthenticatedData,
            authenticationTag: authenticationTag,
            contentEncryptionKey: contentEncryptionKey256
        )
        let decrypter: ContentDecrypter = AESGCMEncryption(contentEncryptionAlgorithm: .A256GCM)
        let plaintext = try! decrypter.decrypt(decryptionContext: context)
        XCTAssertEqual(expectedPlaintext, plaintext)
    }

    /// Tests the `AES` decryption implementation using the header payload interface
    func testEncrypterHeaderPayloadInterfaceEncryptsDataA256GCM() throws {
        let plaintext = "Live long and prosper.".data(using: .ascii)!
        let header = JWEHeader(keyManagementAlgorithm: .RSAOAEP256, contentEncryptionAlgorithm: .A256GCM)
        let symmetricEncryptionContext = try AESGCMEncryption(contentEncryptionAlgorithm: .A256GCM)
            .encrypt(headerData: header.data(), payload: Payload(plaintext), contentEncryptionKey: contentEncryptionKey256)

        // Check if the symmetric encryption was successful by using the CryptoKit framework and not the implemented decrypt method.
        let additionalAuthenticatedData = header.data().base64URLEncodedData()
        let key = CryptoKit.SymmetricKey(data: contentEncryptionKey256)
        let nonce = try CryptoKit.AES.GCM.Nonce(data: symmetricEncryptionContext.initializationVector)
        let encrypted = try CryptoKit.AES.GCM.SealedBox(nonce: nonce, ciphertext: symmetricEncryptionContext.ciphertext, tag: symmetricEncryptionContext.authenticationTag)
        let decrypted = try CryptoKit.AES.GCM.open(encrypted, using: key, authenticating: additionalAuthenticatedData)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testContentEncryptionAlgorithmFeatures() {
        // verify key length
        XCTAssertEqual(32, ContentEncryptionAlgorithm.A256GCM.keyLength)
        XCTAssertEqual(24, ContentEncryptionAlgorithm.A192GCM.keyLength)
        XCTAssertEqual(16, ContentEncryptionAlgorithm.A128GCM.keyLength)
        // verify iv length
        XCTAssertEqual(12, ContentEncryptionAlgorithm.A128GCM.initializationVectorLength)
        XCTAssertEqual(12, ContentEncryptionAlgorithm.A192GCM.initializationVectorLength)
        XCTAssertEqual(12, ContentEncryptionAlgorithm.A256GCM.initializationVectorLength)
        // verify non supported content encryption algorithm throws error upon initialization
        XCTAssertThrowsError(try AESCBCEncryption(contentEncryptionAlgorithm: ContentEncryptionAlgorithm.A256GCM)) { error in
            XCTAssertEqual(error as! JWEError, JWEError.contentEncryptionAlgorithmMismatch)
        }
        // verify key length is checked in initializer
        XCTAssertThrowsError(
            try AESGCMEncryption(contentEncryptionAlgorithm: ContentEncryptionAlgorithm.A256GCM)
                .encrypt(headerData: Data(), payload: Payload(Data()), contentEncryptionKey: Data())
        ) { error in
            XCTAssertEqual(error as! JWEError, JWEError.keyLengthNotSatisfied)
        }
    }
}
// swiftlint:enable force_unwrapping
