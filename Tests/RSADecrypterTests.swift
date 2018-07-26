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

class RSADecrypterTests: CryptoTestCase {

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

    let cipherTextWithAliceKeyEmptyStringBase64 = """
hyOA/tmOclFkj31UPrRb1EnaRMhR5VZg5TrUyfLMtCUlh3grAva0+sSjqt6zSlWK06A6zUieV69aLRbJ0ZactTTqX2CFrhiZ5nUXhzuUya83VKBI0xrGkpQ\
8u1y2Iqgb+gbWsFJdJ41cSpZXRpc16Hhd3klTp7YydYZQUG//PLM5bn359kqpT8meJdGqTceehVxmdqTpVwukh/uqLOE8CBCrT7D/2t18mzApGpm/Su4bVb\
ZggJ5g9MRPSnwgq1GjKNcMa1PKd+/OWB/rIeDmorT8dLrusGeLbwFCj1HEz4z5izamiBiyPh96G0m4ZhPtVhR4Fo3ARj9C037GroDQ2w==
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

    func testDecryptingEmptyStringShouldFail() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)

        XCTAssertThrowsError(try decrypter.decrypt(Data(base64URLEncoded: cipherTextWithAliceKeyEmptyStringBase64)!)) { (error: Error) in
            XCTAssertEqual(error as! RSAError, defaultDecryptionError)
        }
    }

}
