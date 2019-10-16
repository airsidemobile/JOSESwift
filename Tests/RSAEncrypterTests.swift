// swiftlint:disable force_unwrapping
//
//  RSAEncrypterTests.swift
//  Tests
//
//  Created by Carol Capek on 22.11.17.
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

extension RSAError: Equatable {
    public static func == (lhs: RSAError, rhs: RSAError) -> Bool {
        switch (lhs, rhs) {
        case (.cipherTextLenghtNotSatisfied, .cipherTextLenghtNotSatisfied):
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

class RSAEncrypterTests: RSACryptoTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testEncryptingWithAliceKey() {
        guard
            let publicKeyAlice2048 = publicKeyAlice2048,
            let privateKeyAlice2048 = privateKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in AsymmetricKeyAlgorithm.allCases {
            // Skip over direct type
            guard algorithm != .direct else {
                continue
            }

            let encrypter = RSAEncrypter(algorithm: algorithm, publicKey: publicKeyAlice2048)
            guard
                let cipherText = try? encrypter.encrypt(message.data(using: .utf8)!),
                let secKeyAlgorithm = algorithm.secKeyAlgorithm else {
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

        for algorithm in AsymmetricKeyAlgorithm.allCases {
            // Skip over direct type
            guard algorithm != .direct else {
                continue
            }

            let encrypter = RSAEncrypter(algorithm: algorithm, publicKey: publicKeyAlice2048)
            guard let cipherText = try? encrypter.encrypt(message.data(using: .utf8)!) else {
                XCTFail()
                return
            }

            guard let cipherText2 = try? encrypter.encrypt(message.data(using: .utf8)!) else {
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

        for algorithm in AsymmetricKeyAlgorithm.allCases {
            // Skip over direct type
            guard algorithm != .direct else {
                continue
            }

            let encrypterAlice = RSAEncrypter(algorithm: algorithm, publicKey: publicKeyAlice2048)
            let encrypterBob = RSAEncrypter(algorithm: algorithm, publicKey: publicKeyBob2048)

            let cipherTextAlice = try encrypterAlice.encrypt(message.data(using: .utf8)!)
            let cipherTextBob = try encrypterBob.encrypt(message.data(using: .utf8)!)

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

        for algorithm in AsymmetricKeyAlgorithm.allCases {
            // Skip over direct type
            guard algorithm != .direct else {
                continue
            }

            let encrypter = RSAEncrypter(algorithm: algorithm, publicKey: publicKeyBob2048)
            guard
                let cipherText = try? encrypter.encrypt(message.data(using: .utf8)!),
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

        for algorithm in AsymmetricKeyAlgorithm.allCases {
            // Skip over direct type
            guard algorithm != .direct else {
                continue
            }

            let encrypter = RSAEncrypter(algorithm: algorithm, publicKey: publicKeyAlice2048)
            XCTAssertThrowsError(try encrypter.encrypt(Data(count: 300))) { (error: Error) in
                XCTAssertEqual(error as? RSAError, RSAError.plainTextLengthNotSatisfied)
            }
        }
    }

    func testMaximumPlainTextLength() {
        guard let publicKeyAlice2048 = publicKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in AsymmetricKeyAlgorithm.allCases {
            // Skip over direct type
            guard algorithm != .direct else {
                continue
            }

            // RSAES-PKCS1-v1_5 can operate on messages of length up to k - 11 octets (k = octet length of the RSA modulus)
            // See https://tools.ietf.org/html/rfc3447#section-7.2
            let maxMessageLengthInBytes = algorithm.maxMessageLength(for: publicKeyAlice2048)
            let testMessage = Data(count: maxMessageLengthInBytes)

            let encrypter = RSAEncrypter(algorithm: algorithm, publicKey: publicKeyAlice2048)
            XCTAssertNoThrow(try encrypter.encrypt(testMessage), "using algorithm: \(algorithm)")
        }
    }

    func testMaximumPlainTextLengthPlusOne() {
        guard let publicKeyAlice2048 = publicKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in AsymmetricKeyAlgorithm.allCases {
            // Skip over direct type
            guard algorithm != .direct else {
                continue
            }

            let maxMessageLengthInBytes = algorithm.maxMessageLength(for: publicKeyAlice2048)
            let testMessage = Data(count: maxMessageLengthInBytes + 1)

            let encrypter = RSAEncrypter(algorithm: algorithm, publicKey: publicKeyAlice2048)
            XCTAssertThrowsError(try encrypter.encrypt(testMessage)) { (error: Error) in
                XCTAssertEqual(error as? RSAError, RSAError.plainTextLengthNotSatisfied)
            }
        }
    }

}
