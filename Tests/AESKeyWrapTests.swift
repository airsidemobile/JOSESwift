//
//  AESKeyWrapTests.swift
//  Tests
//
//  Created by Daniel Egger on 18.02.20.
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

        let ciphertext = try! AES.keyWrap(rawKey: rawKey, keyEncryptionKey: kek, algorithm: .A128KW)

        XCTAssertEqual(ciphertext, expectedCiphertext)

        // Todo: Decrypt
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

        let ciphertext = try! AES.keyWrap(rawKey: rawKey, keyEncryptionKey: kek, algorithm: .A192KW)

        XCTAssertEqual(ciphertext, expectedCiphertext)

        // Todo: Decrypt
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

        let ciphertext = try! AES.keyWrap(rawKey: rawKey, keyEncryptionKey: kek, algorithm: .A256KW)

        XCTAssertEqual(ciphertext, expectedCiphertext)

        // Todo: Decrypt
    }
}
