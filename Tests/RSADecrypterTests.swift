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
    let cipherTextWithAliceKeyBase64URL = "RHLdaxC52ve0icBLGh9Xn_jNoV3uJlEuLRer8_7OOqY2QCGdWPb8OiuxxjEep8okfvlrw_eheEll6v8xdjpzP2zopVEBoNZ9J8BDKL1Y-tTi176jlGXBXKJdRitsp14sVHx7x-dW9FjiOHEn_CSm3bM2THAJOEtjjeF6vRvxpGxm1KruTbtZ37VTl-vM-e4STda5dCanRPKFemDPYQvjUAF_wuE-P-UeE0fpxDceuCRN3C-H8LL9TIrSETRV_CzPVf6Ki9zJpaZQAnqZh5ix0KhaHFMawV7TJetcKPbCzEHbxAF5ib16mxKFc5Th3QFS3eRKYxjaEdciXWVMCrGfXQ"
    let cipherTextWithBobKeyBase64URL = "Yfy_IpYVHDkBagQgYy2BfgzpkdOYSbCVNIdRj8uy2iBshDrIuAYVbMegMARJcg965GRnGYvqWmgvdEcbBvizOfOdPjbuEWnwnefxRA8_gHzi3J83jhx4vkTQuz1C0nylC1YIAIZjP_-gFXqA5hzAqGzYTQ5p4HScra16rXOoOes9U0MbUT_JbcN2nx1MrNQhYA-yMMTQwm5IxZXeEKijehEtfY6hCQx3OMF_4peNzNwO0ECS_bBZ-JDz8hAv7VONR5tSxvCSt-Xa60K0evj0PkAyULX1MdQUwK4gDNUExsffukeY_POG8papZs-gkvzgzMIk31rMzeuGCe5J6wWcwg"
    let cipherTextWithAliceKeyEmptyStringBase64URL = "hyOA/tmOclFkj31UPrRb1EnaRMhR5VZg5TrUyfLMtCUlh3grAva0+sSjqt6zSlWK06A6zUieV69aLRbJ0ZactTTqX2CFrhiZ5nUXhzuUya83VKBI0xrGkpQ8u1y2Iqgb+gbWsFJdJ41cSpZXRpc16Hhd3klTp7YydYZQUG//PLM5bn359kqpT8meJdGqTceehVxmdqTpVwukh/uqLOE8CBCrT7D/2t18mzApGpm/Su4bVbZggJ5g9MRPSnwgq1GjKNcMa1PKd+/OWB/rIeDmorT8dLrusGeLbwFCj1HEz4z5izamiBiyPh96G0m4ZhPtVhR4Fo3ARj9C037GroDQ2w=="

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
        let plainText = try! decrypter.decrypt(Data(base64URLEncoded: cipherTextWithAliceKeyBase64URL)!)

        XCTAssertEqual(plainText, message.data(using: .utf8))
    }

    func testDecryptingWithBobKey() {
        guard privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyBob2048!)
        let plainText = try! decrypter.decrypt(Data(base64URLEncoded: cipherTextWithBobKeyBase64URL)!)

        XCTAssertEqual(plainText, message.data(using: .utf8))
    }

    func testDecryptingAliceSecretWithBobKey() {
        guard privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyBob2048!)

        // Decrypting with the wrong key should throw an error
        XCTAssertThrowsError(try decrypter.decrypt(Data(base64URLEncoded: cipherTextWithAliceKeyBase64URL)!)) { (error: Error) in
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
        XCTAssertThrowsError(try decrypter.decrypt(Data(base64URLEncoded: cipherTextWithBobKeyBase64URL)!)) { (error: Error) in
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

        XCTAssertThrowsError(try decrypter.decrypt(Data(base64URLEncoded: cipherTextWithAliceKeyEmptyStringBase64URL)!)) { (error: Error) in
            XCTAssertEqual(error as! RSAError, defaultDecryptionError)
        }
    }

}
