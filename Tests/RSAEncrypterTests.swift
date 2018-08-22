//
//  RSAEncrypterTests.swift
//  Tests
//
//  Created by Carol Capek on 22.11.17.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
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
    public static func ==(lhs: RSAError, rhs: RSAError) -> Bool {
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

class RSAEncrypterTests: CryptoTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testEncryptingWithAliceKey() {
        guard publicKeyAlice2048 != nil, privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let encrypter = RSAEncrypter(algorithm: .RSA1_5, publicKey: publicKeyAlice2048!)
        guard let cipherText = try? encrypter.encrypt(message.data(using: .utf8)!) else {
            XCTFail()
            return
        }

        var decryptionError: Unmanaged<CFError>?
        guard let plainTextData = SecKeyCreateDecryptedData(privateKeyAlice2048!, .rsaEncryptionPKCS1, cipherText as CFData, &decryptionError) else {
            XCTFail()
            return
        }

        XCTAssertEqual(String(data: plainTextData as Data, encoding: .utf8), message)
    }

    func testEncryptingTwiceWithAliceKey() {
        guard publicKeyAlice2048 != nil, privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let encrypter = RSAEncrypter(algorithm: .RSA1_5, publicKey: publicKeyAlice2048!)
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

    func testEncryptingWithAliceAndBobKey() {
        guard publicKeyAlice2048 != nil, privateKeyAlice2048 != nil, publicKeyBob2048 != nil, privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        let encrypterAlice = RSAEncrypter(algorithm: .RSA1_5, publicKey: publicKeyAlice2048!)
        let encrypterBob = RSAEncrypter(algorithm: .RSA1_5, publicKey: publicKeyBob2048!)

        guard let cipherTextAlice = try? encrypterAlice.encrypt(message.data(using: .utf8)!) else {
            XCTFail()
            return
        }
        guard let cipherTextBob = try? encrypterBob.encrypt(message.data(using: .utf8)!) else {
            XCTFail()
            return
        }

        // Cipher texts have to differ (different keys)
        XCTAssertNotEqual(cipherTextAlice, cipherTextBob)
    }

    func testEncryptingWithBobKey() {
        guard publicKeyBob2048 != nil, privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        let encrypter = RSAEncrypter(algorithm: .RSA1_5, publicKey: publicKeyBob2048!)
        guard let cipherText = try? encrypter.encrypt(message.data(using: .utf8)!) else {
            XCTFail()
            return
        }

        var decryptionError: Unmanaged<CFError>?
        guard let plainTextData = SecKeyCreateDecryptedData(privateKeyBob2048!, .rsaEncryptionPKCS1, cipherText as CFData, &decryptionError) else {
            XCTFail()
            return
        }

        XCTAssertEqual(String(data: plainTextData as Data, encoding: .utf8), message)
    }

    func testPlainTextTooLong() {
        guard publicKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let encrypter = RSAEncrypter(algorithm: .RSA1_5, publicKey: publicKeyAlice2048!)
        XCTAssertThrowsError(try encrypter.encrypt(Data(count:300))) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.plainTextLengthNotSatisfied)
        }
    }

    func testMaximumPlainTextLength() {
        guard publicKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        // RSAES-PKCS1-v1_5 can operate on messages of length up to k - 11 octets (k = octet length of the RSA modulus)
        // See https://tools.ietf.org/html/rfc3447#section-7.2
        let maxMessageLengthInBytes = SecKeyGetBlockSize(publicKeyAlice2048!) - 11
        let testMessage = Data(count: maxMessageLengthInBytes)

        let encrypter = RSAEncrypter(algorithm: .RSA1_5, publicKey: publicKeyAlice2048!)
        XCTAssertNoThrow(try encrypter.encrypt(testMessage))
    }

    func testMaximumPlainTextLengthPlusOne() {
        guard publicKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let maxMessageLengthInBytes = SecKeyGetBlockSize(publicKeyAlice2048!) - 11
        let testMessage = Data(count: maxMessageLengthInBytes + 1)

        let encrypter = RSAEncrypter(algorithm: .RSA1_5, publicKey: publicKeyAlice2048!)
        XCTAssertThrowsError(try encrypter.encrypt(testMessage)) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.plainTextLengthNotSatisfied)
        }
    }

}
