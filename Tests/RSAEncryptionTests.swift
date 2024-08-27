// swiftlint:disable force_unwrapping
//
//  RSAEncryptionTests.swift
//  Tests
//
//  Created by Carol Capek on 22.11.17.
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

extension RSAError: Equatable {
    public static func == (lhs: RSAError, rhs: RSAError) -> Bool {
        switch (lhs, rhs) {
        case (.cipherTextLengthNotSatisfied, .cipherTextLengthNotSatisfied):
            return true
        case (.plainTextLengthNotSatisfied, .plainTextLengthNotSatisfied):
            return true
        case (.decryptingFailed(let a), .decryptingFailed(let b)):
            return a == b
        default:
            return false
        }
    }
}

class RSAEncryptionTests: RSACryptoTestCase {
    let keyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.RSA1_5, .RSAOAEP, .RSAOAEP256]

    func testEncryptingWithAliceKey() {
        guard
            let publicKeyAlice2048 = publicKeyAlice2048,
            let privateKeyAlice2048 = privateKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            guard
                let cipherText = try? RSA.encrypt(message.data(using: .utf8)!, with: publicKeyAlice2048, and: algorithm),
                let secKeyAlgorithm = algorithm.secKeyAlgorithm
            else {
                XCTFail()
                return
            }

            var decryptionError: Unmanaged<CFError>?
            guard let plainTextData = SecKeyCreateDecryptedData(privateKeyAlice2048, secKeyAlgorithm, cipherText as CFData, &decryptionError) else {
                XCTFail()
                return
            }

            XCTAssertEqual(String(data: plainTextData as Data, encoding: .utf8), message)
        }
    }

    func testEncryptingTwiceWithAliceKey() {
        guard let publicKeyAlice2048 = publicKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            guard let cipherText = try? RSA.encrypt(message.data(using: .utf8)!, with: publicKeyAlice2048, and: algorithm) else {
                XCTFail()
                return
            }

            guard let cipherText2 = try? RSA.encrypt(message.data(using: .utf8)!, with: publicKeyAlice2048, and: algorithm) else {
                XCTFail()
                return
            }

            // Cipher texts differ because of random padding, see https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Padding_schemes
            XCTAssertNotEqual(cipherText, cipherText2)
        }
    }

    func testEncryptingWithAliceAndBobKey() throws {
        guard
            let publicKeyAlice2048 = publicKeyAlice2048,
            let publicKeyBob2048 = publicKeyBob2048 else {
                XCTFail()
                return
        }

        for algorithm in keyManagementModeAlgorithms {
            let cipherTextAlice = try RSA.encrypt(message.data(using: .utf8)!, with: publicKeyAlice2048, and: algorithm)
            let cipherTextBob = try RSA.encrypt(message.data(using: .utf8)!, with: publicKeyBob2048, and: algorithm)

            // Cipher texts have to differ (different keys)
            XCTAssertNotEqual(cipherTextAlice, cipherTextBob)
        }
    }

    func testEncryptingWithBobKey() {
        guard
            let publicKeyBob2048 = publicKeyBob2048,
            let privateKeyBob2048 = privateKeyBob2048 else {
                XCTFail()
                return
        }

        for algorithm in keyManagementModeAlgorithms {
            guard
                let cipherText = try? RSA.encrypt(message.data(using: .utf8)!, with: publicKeyBob2048, and: algorithm),
                let secKeyAlgorithm = algorithm.secKeyAlgorithm else {
                    XCTFail()
                    return
            }

            var decryptionError: Unmanaged<CFError>?
            guard let plainTextData = SecKeyCreateDecryptedData(privateKeyBob2048, secKeyAlgorithm, cipherText as CFData, &decryptionError) else {
                XCTFail()
                return
            }

            XCTAssertEqual(String(data: plainTextData as Data, encoding: .utf8), message)
        }
    }

    func testPlainTextTooLong() {
        guard let publicKeyAlice2048 = publicKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            XCTAssertThrowsError(try RSA.encrypt(Data(count: 300), with: publicKeyAlice2048, and: algorithm)) { (error: Error) in
                XCTAssertEqual(error as? RSAError, RSAError.plainTextLengthNotSatisfied)
            }
        }
    }

    func testMaximumPlainTextLength() {
        guard let publicKeyAlice2048 = publicKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            // RSAES-PKCS1-v1_5 can operate on messages of length up to k - 11 octets (k = octet length of the RSA modulus)
            // See https://tools.ietf.org/html/rfc3447#section-7.2
            let maxMessageLengthInBytes = algorithm.maxMessageLength(for: publicKeyAlice2048)!
            let testMessage = Data(count: maxMessageLengthInBytes)

            XCTAssertNoThrow(try RSA.encrypt(testMessage, with: publicKeyAlice2048, and: algorithm), "using algorithm: \(algorithm)")
        }
    }

    func testMaximumPlainTextLengthPlusOne() {
        guard let publicKeyAlice2048 = publicKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            let maxMessageLengthInBytes = algorithm.maxMessageLength(for: publicKeyAlice2048)!
            let testMessage = Data(count: maxMessageLengthInBytes + 1)

            XCTAssertThrowsError(try RSA.encrypt(testMessage, with: publicKeyAlice2048, and: algorithm)) { (error: Error) in
                XCTAssertEqual(error as? RSAError, RSAError.plainTextLengthNotSatisfied)
            }
        }
    }
}
// swiftlint:enable force_unwrapping
