//
//  RSADecrypterTests.swift
//  Tests
//
//  Created by Carol Capek on 23.11.17.
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

class RSADecrypterTests: RSACryptoTestCase {

    // Cipher texts are generated with `openssl rsautl`
    // `printf` is used because `echo` appends a newline at the end of the string

    // printf "The true sign of intelligence is not knowledge but imagination." | openssl rsautl -encrypt -pubin -inkey alice.pub.pem -out >(base64)
    let cipherTextWithAliceKeyBase64 = """
gurwC3C0X+Q3W1itUlq6fH4xpRMTnp19VCqSw2i9+/yBdwLriCOzG2K5bOaGbC/e1CgtV2c26uLW0zkj6Aw2F5dFttFbVi+AXEBv3L1H3iXOT6lH2Dv5luQ\
fu/lA9mQbFoKNjp+0WHSMB3jmRdX9mC4GoIPP8vQKaCa8cNw5RxtP2M4TjMPJQYrnRn3Jsx0rSxPaBse9HyOtr43QH4B51VLyExmNHWyNSt28wFTav+EaBx\
KwawQvhC/447MoBlhtE3bYolvfu5vY3uFV/Dh8Ip5zRvZuE6NwRZN2EdWyR35iphyCgcKufJn9J1oYYZ0b2Sgbrw1e0naWkgYm6djXFw==
"""

    // printf "The true sign of intelligence is not knowledge but imagination." | openssl rsautl -encrypt -pubin -inkey bob.pub.pem -out >(base64)
    let cipherTextWithBobKeyBase64 = """
TA13QruprKdRMt6JVE6dJWKF6bRUZyQLCZKA1KnJCsQx7nprXjYUFlAouhoVfcKPUTuMiyKSMFvkDOqcoJwP3zz14CFA+nI3OeAHiYvMasoJ/H6xlUj1UXh\
KRZy3cjd581pzxsPKFplBAuUAYacgIpHW+ZuAjGD+KJzQ6N7TFuWUZxXktsIL2mOhvdRWR0Le5pbgBSgkXAOyLUGa66AEZDk42+W7MomNYaDDsxfYHg3LzW\
sVyhqpFuZQ6hhklG9lJr6OBBuk/+pcJYdHuYEuLnJhPeKqF/9xgMOU0e0xLMtkQW+IfDMlm0oAVavHrxk7A4T5L9+yjuxNjN16k2Rqiw==
"""

    let defaultDecryptionError = RSAError.decryptingFailed(description: "The operation couldn’t be completed. (OSStatus error -50 - RSAdecrypt wrong input (err -1))")

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testDecryptingWithAliceKey() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)
        let decryptedData = try! decrypter.decrypt(Data(base64Encoded: cipherTextWithAliceKeyBase64)!)
        let decryptedMessage = String(data: decryptedData, encoding: String.Encoding.utf8)

        XCTAssertEqual(decryptedMessage, message)
    }

    func testDecryptingWithBobKey() {
        guard privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyBob2048!)
        let decryptedData = try! decrypter.decrypt(Data(base64URLEncoded: cipherTextWithBobKeyBase64)!)
        let decryptedMessage = String(data: decryptedData, encoding: String.Encoding.utf8)

        XCTAssertEqual(decryptedMessage, message)
    }

    func testDecryptingAliceSecretWithBobKey() {
        guard privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyBob2048!)

        // Decrypting with the wrong key should throw an error
        XCTAssertThrowsError(try decrypter.decrypt(Data(base64URLEncoded: cipherTextWithAliceKeyBase64)!)) { (error: Error) in
            XCTAssertEqual(error as! RSAError, defaultDecryptionError)
        }
    }

    func testDecryptingBobSecretWithAliceKey() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)

        // Decrypting with the wrong key should throw an error
        XCTAssertThrowsError(try decrypter.decrypt(Data(base64URLEncoded: cipherTextWithBobKeyBase64)!)) { (error: Error) in
            XCTAssertEqual(error as! RSAError, defaultDecryptionError)
        }
    }

    func testCipherTextLengthTooLong() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)
        XCTAssertThrowsError(try decrypter.decrypt(Data(count: 300))) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

    func testCipherTextLengthZero() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)
        XCTAssertThrowsError(try decrypter.decrypt(Data(count: 0))) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

    func testCipherTextLengthExactlyRight() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        // Length checking: If the length of the ciphertext C is not k octets
        // (or if k < 11), output "decryption error" and stop.
        // See 7.2.2 Decryption operation RSAES-PKCS1-V1_5-DECRYPT (K, C)
        // https://tools.ietf.org/html/rfc3447#section-7.2.2
        let cipherTextLengthInBytes = SecKeyGetBlockSize(privateKeyAlice2048!)
        let testMessage = Data(count: cipherTextLengthInBytes)

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)

        XCTAssertThrowsError(try decrypter.decrypt(testMessage)) { (error: Error) in
            // Should throw "decryption failed", but
            // should _not_ throw cipherTextLenghtNotSatisfied
            XCTAssertNotEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

    func testCipherTextLengthTooLongByOneByte() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let cipherTextLengthInBytes = SecKeyGetBlockSize(privateKeyAlice2048!)
        let testMessage = Data(count: cipherTextLengthInBytes + 1)

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)
        XCTAssertThrowsError(try decrypter.decrypt(testMessage)) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

    func testCipherTextLengthTooShortByOneByte() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let cipherTextLengthInBytes = SecKeyGetBlockSize(privateKeyAlice2048!)
        let testMessage = Data(count: cipherTextLengthInBytes - 1)

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)
        XCTAssertThrowsError(try decrypter.decrypt(testMessage)) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

}
