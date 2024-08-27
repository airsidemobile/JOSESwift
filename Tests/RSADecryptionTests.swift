// swiftlint:disable force_unwrapping
//
//  RSADecryptionTests.swift
//  Tests
//
//  Created by Carol Capek on 23.11.17.
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

class RSADecryptionTests: RSACryptoTestCase {
    let keyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.RSA1_5, .RSAOAEP, .RSAOAEP256]

    // Cipher texts are generated with `openssl rsautl`.
    // `printf` is used because `echo` appends a newline at the end of the string.

    // printf "The true sign of intelligence is not knowledge but imagination." | openssl rsautl -encrypt -pubin -inkey alice.pub.pem -out >(base64)
    let cipherTextWithAliceKeyBase64 = """
        gurwC3C0X+Q3W1itUlq6fH4xpRMTnp19VCqSw2i9+/yBdwLriCOzG2K5bOaGbC/e1CgtV2c26uLW0zkj6Aw2F5dFttFbVi+AXEBv3L1H3iXOT6l\
        H2Dv5luQfu/lA9mQbFoKNjp+0WHSMB3jmRdX9mC4GoIPP8vQKaCa8cNw5RxtP2M4TjMPJQYrnRn3Jsx0rSxPaBse9HyOtr43QH4B51VLyExmNHW\
        yNSt28wFTav+EaBxKwawQvhC/447MoBlhtE3bYolvfu5vY3uFV/Dh8Ip5zRvZuE6NwRZN2EdWyR35iphyCgcKufJn9J1oYYZ0b2Sgbrw1e0naWk\
        gYm6djXFw==
        """

    // printf "The true sign of intelligence is not knowledge but imagination." | openssl pkeyutl -encrypt -pubin -inkey alice.pub.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out >(base64)
    //  *NOTE*: openssl v1.1.x is required to encrypt data using RSAES-OAEP with SHA256 digest.
    let cipherTextWithAliceOAEPSHA256Base64 = """
        HtL3/k9aiCzON4dEAK930LXvxoWgu2cXHj011FAY4Z++CikiPn5gt/TLFEEV6c4MyMUN8Pj796XwO5a9LRfsV+XWjb5WIAUXewgdKYC1NBFf/q\
        Ip+NixeO6oo0nh5NlApJgphRIy1en9ARoz0rIzayt0Py4QOEse7OHLUnDA7PP8vp0X1pyqEG9FZaPViH4+/1zwvEjBVo4N5K4Zl4jqzFYTOkm4\
        hhfRBJrMuiGEsWaGZ9qzn5zuyP3hwZeTsArDSvLMt/TwhRpwNp4O9G23ht2gM5N3C76eI8re08zq9L7jggZSbPO1qVY5dQGBJhS2EEXAVxTzgv\
        xRPbteU7pSBA==
        """

    // printf "The true sign of intelligence is not knowledge but imagination." | openssl pkeyutl -encrypt -pubin -inkey alice.pub.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -out >(base64)
    //  *NOTE*: openssl v1.1.x is required to encrypt data using RSAES-OAEP with SHA256 digest.
    let cipherTextWithAliceOAEPSHA1Base64 = """
        bx+Sg8AfSLUGUL/ogL6LZLJdX62N7sYA413SG5sfaAunpyrH3/SCJNTsjQow8zk99jbbiSABWKowDb8tfIwY0SHiU/aKW46f7FeP/70vF2zOefr\
        LnVjw1hE9mJi/P7qP66Md8lNC7iRRDtluAHzPE7Hr8E4Xam2lEmZOXsE0lFnHf0eyG23rezGfnJ4lIY40GK926qyjTkSvtHJa57bzfP3Bxj61NK\
        uuc1nX1oTg9bkHLnqpTK4YtNZ1Roj5qTbNvA0BKyz6+xDGMqiCTLkkjadh2Nc1mMrThkul8ehGUi89i72aydwt7rRtM5O4Y3x1mLv4Z7q8ruxa+\
        xjVJh5uQQ==
        """

    // printf "The true sign of intelligence is not knowledge but imagination." | openssl rsautl -encrypt -pubin -inkey bob.pub.pem -out >(base64)
    let cipherTextWithBobKeyBase64 = """
        TA13QruprKdRMt6JVE6dJWKF6bRUZyQLCZKA1KnJCsQx7nprXjYUFlAouhoVfcKPUTuMiyKSMFvkDOqcoJwP3zz14CFA+nI3OeAHiYvMasoJ/H6\
        xlUj1UXhKRZy3cjd581pzxsPKFplBAuUAYacgIpHW+ZuAjGD+KJzQ6N7TFuWUZxXktsIL2mOhvdRWR0Le5pbgBSgkXAOyLUGa66AEZDk42+W7Mo\
        mNYaDDsxfYHg3LzWsVyhqpFuZQ6hhklG9lJr6OBBuk/+pcJYdHuYEuLnJhPeKqF/9xgMOU0e0xLMtkQW+IfDMlm0oAVavHrxk7A4T5L9+yjuxNj\
        N16k2Rqiw==
        """

    // printf "The true sign of intelligence is not knowledge but imagination." | openssl pkeyutl -encrypt -pubin -inkey bob.pub.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out >(base64)
    //  *NOTE*: openssl v1.1.x is required to encrypt data using RSAES-OAEP with SHA256 digest.
    let cipherTextWithBobKeyOAEPSHA256Base64 = """
        IUCsUQzcyL/iuwWpgXK/TgyrsxuSbKKAXq1bd6wlRf7O+9UBlQAenAzXkhRchBOrCYbS1Bs2IwN3gu51RiVsuOg5oHxxKIbtfnbqwtw9beV02oR\
        ETCSZ5wPFC/tlYYYloGYR3O47VF5o+NV4qKOE6jbjBEknMAwdN1eoGb0LmF9kUvt9jCLkI1Jt3Cqs8fV9nxqI4Iyzn6hjlvRJk82Ah/q86XfNCQ\
        3KcXrUUR7GQ1BY5qR+wu76HpI5a1yZmXrl2HL1MMtxMLxmawtNUWsMVm1lrq1jWw1TQTktV5zRl4p6DDlSSfEacwaBsVyr0SIKg8fPxP9olRvXZ\
        m+AS53GTQ==
        """

    // printf "The true sign of intelligence is not knowledge but imagination." | openssl pkeyutl -encrypt -pubin -inkey bob.pub.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -out >(base64)
    //  *NOTE*: openssl v1.1.x is required to encrypt data using RSA-OAEP with SHA256 digest
    let cipherTextWithBobKeyOAEPSHA1Base64 = """
        aEe2ns+ouW1sLiCo6Zq+h5N1MNgYiiY/xIkvjot8xo8mlvX4TFnygzr1r1Bu4uk+Ra2ZRHYJ/Cjtb62V3vebfsCxd6VEVJmf8ZkDsDk8EDHufgM\
        0ss1PvWg8uEgTXdDNDlA3yUurEDMY6agB52LqRjkK8zAP0tiOuDRYTNFn8ENNXBsyhbQOLE7PwOTCBjYxpglOcGksr7J+m+pVThB40/07DYLHoh\
        mbzb6k+wWYvdNiUZ6g8s5z5azK41azvNCPoDmAIaN4+F7kFzTNUAKsKo9eTFjKn4a/bzp1Fz0GmRKJnpdfzoWpkC73zFPT5GMbuhC9XG0WBtI8i\
        8GmvJ5UwA==
        """

    let rsaDecryptionError = RSAError.decryptingFailed(description: """
        The operation couldn’t be completed. (OSStatus error -50 - RSAdecrypt wrong input (err -27))
        """)

    /// Dictionary of ciphertexts for each available Asymmetric key algorithm generate via openssl with Alice's public key
    lazy var aliceCipherTextDict: [String: String] = {
        [
            KeyManagementAlgorithm.RSA1_5.rawValue: self.cipherTextWithAliceKeyBase64,
            KeyManagementAlgorithm.RSAOAEP256.rawValue: self.cipherTextWithAliceOAEPSHA256Base64,
            KeyManagementAlgorithm.RSAOAEP.rawValue: self.cipherTextWithAliceOAEPSHA1Base64
        ]
    }()

    /// Dictionary of ciphertexts for each available Asymmetric algorithm generate via openssl with Bob's public key
    lazy var bobCipherTextDict: [String: String] = {
        [
            KeyManagementAlgorithm.RSA1_5.rawValue: self.cipherTextWithBobKeyBase64,
            KeyManagementAlgorithm.RSAOAEP256.rawValue: self.cipherTextWithBobKeyOAEPSHA256Base64,
            KeyManagementAlgorithm.RSAOAEP.rawValue: self.cipherTextWithBobKeyOAEPSHA1Base64

        ]
    }()

    func testDecryptingWithAliceKey() {
        guard let privateKeyAlice2048 = privateKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            let ciphertext = Data(base64Encoded: aliceCipherTextDict[algorithm.rawValue]!)!
            let decryptedData = try! RSA.decrypt(ciphertext, with: privateKeyAlice2048, and: algorithm)
            let decryptedMessage = String(data: decryptedData, encoding: String.Encoding.utf8)

            XCTAssertEqual(decryptedMessage, message)
        }
    }

    func testDecryptingWithBobKey() {
        guard privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            let ciphertext = Data(base64URLEncoded: bobCipherTextDict[algorithm.rawValue]!)!
            let decryptedData = try! RSA.decrypt(ciphertext, with: privateKeyBob2048!, and: algorithm)
            let decryptedMessage = String(data: decryptedData, encoding: String.Encoding.utf8)

            XCTAssertEqual(decryptedMessage, message)
        }
    }

    func testDecryptingAliceSecretWithBobKey() {
        guard privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            // Decrypting with the wrong key should throw an error
            let ciphertext = Data(base64URLEncoded: aliceCipherTextDict[algorithm.rawValue]!)!
            XCTAssertThrowsError(try RSA.decrypt(ciphertext, with: privateKeyBob2048!, and: algorithm)) { (error: Error) in
                XCTAssertEqual(error as? RSAError, rsaDecryptionError)
            }
        }
    }

    func testDecryptingBobSecretWithAliceKey() {
        guard let privateKeyAlice2048 = privateKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            // Decrypting with the wrong key should throw an error
            let ciphertext = Data(base64URLEncoded: bobCipherTextDict[algorithm.rawValue]!)!
            XCTAssertThrowsError(try RSA.decrypt(ciphertext, with: privateKeyAlice2048, and: algorithm)) { (error: Error) in
                XCTAssertEqual(error as? RSAError, rsaDecryptionError)
            }
        }
    }

    func testCipherTextLengthTooLong() {
        guard let privateKeyAlice2048 = privateKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            let ciphertext = Data(count: 300)
            XCTAssertThrowsError(try RSA.decrypt(ciphertext, with: privateKeyAlice2048, and: algorithm)) { (error: Error) in
                XCTAssertEqual(error as? RSAError, RSAError.cipherTextLengthNotSatisfied)
            }
        }
    }

    func testCipherTextLengthZero() {
        guard let privateKeyAlice2048 = privateKeyAlice2048 else {
            XCTFail()
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            let ciphertext = Data(count: 0)
            XCTAssertThrowsError(try RSA.decrypt(ciphertext, with: privateKeyAlice2048, and: algorithm)) { (error: Error) in
                XCTAssertEqual(error as? RSAError, RSAError.cipherTextLengthNotSatisfied)
            }
        }
    }

    func testCipherTextLengthExactlyRight() {
        guard let privateKeyAlice2048 = privateKeyAlice2048 else {
            XCTFail()
            return
        }

        let secKeyBlockSize = SecKeyGetBlockSize(privateKeyAlice2048)
        let testMessage = Data(count: secKeyBlockSize)

        for algorithm in keyManagementModeAlgorithms {
            XCTAssertThrowsError(try RSA.decrypt(testMessage, with: privateKeyAlice2048, and: algorithm)) { (error: Error) in
                // Should throw "decryption failed", but
                // should _not_ throw cipherTextLenghtNotSatisfied
                XCTAssertNotEqual(error as? RSAError, RSAError.cipherTextLengthNotSatisfied)
            }
        }
    }

    func testCipherTextLengthTooLongByOneByte() {
        guard let privateKeyAlice2048 = privateKeyAlice2048 else {
            XCTFail()
            return
        }

        let cipherTextLengthInBytes = SecKeyGetBlockSize(privateKeyAlice2048)
        let testMessage = Data(count: cipherTextLengthInBytes + 1)

        for algorithm in keyManagementModeAlgorithms {
            XCTAssertThrowsError(try RSA.decrypt(testMessage, with: privateKeyAlice2048, and: algorithm)) { (error: Error) in
                XCTAssertEqual(error as? RSAError, RSAError.cipherTextLengthNotSatisfied)
            }
        }
    }

    func testCipherTextLengthTooShortByOneByte() {
        guard let privateKeyAlice2048 = privateKeyAlice2048 else {
            XCTFail()
            return
        }

        let cipherTextLengthInBytes = SecKeyGetBlockSize(privateKeyAlice2048)
        let testMessage = Data(count: cipherTextLengthInBytes - 1)

        for algorithm in keyManagementModeAlgorithms {
            XCTAssertThrowsError(try RSA.decrypt(testMessage, with: privateKeyAlice2048, and: algorithm)) { (error: Error) in
                XCTAssertEqual(error as? RSAError, RSAError.cipherTextLengthNotSatisfied)
            }
        }
    }

}
// swiftlint:enable force_unwrapping
