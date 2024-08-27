//
//  AESKeyWrapTests.swift
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

// Test data taken from RFC-3394, 4 (https://tools.ietf.org/html/rfc3394#section-4).
class AESKeyWrapTests: XCTestCase {
    func testA128KW() {
        let rawKey = """
            00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
            """.hexadecimalToData()!

        let kek = """
            00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
            """.hexadecimalToData()!

        let expectedCiphertext = """
            1f a6 8b 0a 81 12 b4 47 ae f3 4b d8 fb 5a 7b 82 9d 3e 86 23 71 d2 cf e5
            """.hexadecimalToData()!

        let ciphertext = try! AES.wrap(rawKey: rawKey, keyEncryptionKey: kek, algorithm: .A128KW)

        XCTAssertEqual(ciphertext, expectedCiphertext)

        let unwrappedKey = try! AES.unwrap(wrappedKey: ciphertext, keyEncryptionKey: kek, algorithm: .A128KW)

        XCTAssertEqual(unwrappedKey, rawKey)
    }

    func testA192KW() {
        let rawKey = """
            00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
            """.hexadecimalToData()!

        let kek = """
            00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17
            """.hexadecimalToData()!

        let expectedCiphertext = """
            96 77 8b 25 ae 6c a4 35 f9 2b 5b 97 c0 50 ae d2 46 8a b8 a1 7a d8 4e 5d
            """.hexadecimalToData()!

        let ciphertext = try! AES.wrap(rawKey: rawKey, keyEncryptionKey: kek, algorithm: .A192KW)

        XCTAssertEqual(ciphertext, expectedCiphertext)

        let unwrappedKey = try! AES.unwrap(wrappedKey: ciphertext, keyEncryptionKey: kek, algorithm: .A192KW)

        XCTAssertEqual(unwrappedKey, rawKey)
    }

    func testA256KW() {
        let rawKey = """
            00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
            """.hexadecimalToData()!

        let kek = """
            00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
            """.hexadecimalToData()!

        let expectedCiphertext = """
            64 e8 c3 f9 ce 0f 5b a2 63 e9 77 79 05 81 8a 2a 93 c8 19 1e 7d 6e 8a e7
            """.hexadecimalToData()!

        let ciphertext = try! AES.wrap(rawKey: rawKey, keyEncryptionKey: kek, algorithm: .A256KW)

        XCTAssertEqual(ciphertext, expectedCiphertext)

        let unwrappedKey = try! AES.unwrap(wrappedKey: ciphertext, keyEncryptionKey: kek, algorithm: .A256KW)

        XCTAssertEqual(unwrappedKey, rawKey)
    }

    func testKeyWrapWithTooLargeKey() throws {
        let rawKey = Data(count: 16)
        let tooLargeKeyEncryptionKey = Data(count: (128 / 8) + 1)

        XCTAssertThrowsError(
            try AES.wrap(rawKey: rawKey, keyEncryptionKey: tooLargeKeyEncryptionKey, algorithm: .A128KW),
            "Invalid keysize"
        ) { error in
            XCTAssertEqual(error as! AESError, AESError.keyLengthNotSatisfied)
        }
    }

    func testKeyWrapWithTooSmallKey() throws {
        let rawKey = Data(count: 16)
        let tooLargeKeyEncryptionKey = Data(count: (128 / 8) - 1)

        XCTAssertThrowsError(
            try AES.wrap(rawKey: rawKey, keyEncryptionKey: tooLargeKeyEncryptionKey, algorithm: .A128KW),
            "Invalid keysize"
        ) { error in
            XCTAssertEqual(error as! AESError, AESError.keyLengthNotSatisfied)
        }
    }

    func testKeyUnwrapWithTooLargeKey() throws {
        let wrappedKey = Data(count: 16)
        let tooLargeKeyEncryptionKey = Data(count: (128 / 8) + 1)

        XCTAssertThrowsError(
            try AES.unwrap(wrappedKey: wrappedKey, keyEncryptionKey: tooLargeKeyEncryptionKey, algorithm: .A128KW),
            "Invalid keysize"
        ) { error in
            XCTAssertEqual(error as! AESError, AESError.keyLengthNotSatisfied)
        }
    }

    func testKeyUnwrapWithTooSmallKey() throws {
        let wrappedKey = Data(count: 16)
        let tooSmallKeyEncryptionKey = Data(count: (128 / 8) - 1)

        XCTAssertThrowsError(
            try AES.unwrap(wrappedKey: wrappedKey, keyEncryptionKey: tooSmallKeyEncryptionKey, algorithm: .A128KW),
            "Invalid keysize"
        ) { error in
            XCTAssertEqual(error as! AESError, AESError.keyLengthNotSatisfied)
        }
    }

    func testKeyWrapEmptyKey() throws {
        let rawKey = Data()
        let keyEncryptionKey = Data(count: 128 / 8)

        XCTAssertThrowsError(
            try AES.wrap(rawKey: rawKey, keyEncryptionKey: keyEncryptionKey, algorithm: .A128KW),
            "Invalid keysize"
        ) { error in
            XCTAssertEqual(error as! AESError, AESError.encryptingFailed(description: ""))
        }
    }

    func testKeyUnwrapEmptyKey() throws {
        let wrappedKey = Data()
        let keyEncryptionKey = Data(count: 128 / 8)

        XCTAssertThrowsError(
            try AES.unwrap(wrappedKey: wrappedKey, keyEncryptionKey: keyEncryptionKey, algorithm: .A128KW),
            "Invalid keysize"
        ) { error in
            XCTAssertEqual(error as! AESError, AESError.decryptingFailed(description: ""))
        }
    }

    func testAESGCMisNotUsableInCommonCrypto() {
        for algorithm in [ContentEncryptionAlgorithm.A256GCM, ContentEncryptionAlgorithm.A128GCM] {
            XCTAssertThrowsError(
                try AES.encrypt(Data(), with: Data(), using: algorithm, and: Data())
            ) { error in
                XCTAssertEqual(error as! AESError, AESError.invalidAlgorithm)
            }
            XCTAssertThrowsError(
                try AES.decrypt(cipherText: Data(), with: Data(), using: algorithm, and: Data())
            ) { error in
                XCTAssertEqual(error as! AESError, AESError.invalidAlgorithm)
            }
        }
    }
}
// swiftlint:enable force_unwrapping
