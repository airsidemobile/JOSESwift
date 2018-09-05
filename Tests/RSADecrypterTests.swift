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
    // printf "The true sign of intelligence is not knowledge but imagination." | openssl rsautl -encrypt -oaep -pubin -inkey alice.pub.pem -out >(base64)
    let cipherTextWithAliceKeyBase64OAEP = """
S55OZCsH+Vg3J2xRqmwQj4CG58c0gHfvxhJOgAKWkWd3N7m+jbn7NRo35ZoP1q/dwutnTQxHg4S9S68NpfY22mOOtHR6wiMz5M/ll6f+EKhwwFQOFzXAS8m\
ihiFINYSdp8BjayvxAlee4HiTygH+clw8nxXu64soHx23Q1kDqqqYUdO/7xzM/WrsN0Be4RoRnqDgX/mxC4AnjHaGA2TlW/Uv+8qHRrO/4OfmByJMW2tkpD\
jEhB7NQ34ig4RohAw+eNsgC9Tm7KBQEsTlv6A4wPFHbYRMbK5W2HGuICOUV+xfVuzyoPhK5Jl6bg9GQKD15VkyRlEkZRy2FPRF+ETuEA==
"""

    // printf "The true sign of intelligence is not knowledge but imagination." | openssl rsautl -encrypt -pubin -inkey bob.pub.pem -out >(base64)
    let cipherTextWithBobKeyBase64 = """
TA13QruprKdRMt6JVE6dJWKF6bRUZyQLCZKA1KnJCsQx7nprXjYUFlAouhoVfcKPUTuMiyKSMFvkDOqcoJwP3zz14CFA+nI3OeAHiYvMasoJ/H6xlUj1UXh\
KRZy3cjd581pzxsPKFplBAuUAYacgIpHW+ZuAjGD+KJzQ6N7TFuWUZxXktsIL2mOhvdRWR0Le5pbgBSgkXAOyLUGa66AEZDk42+W7MomNYaDDsxfYHg3LzW\
sVyhqpFuZQ6hhklG9lJr6OBBuk/+pcJYdHuYEuLnJhPeKqF/9xgMOU0e0xLMtkQW+IfDMlm0oAVavHrxk7A4T5L9+yjuxNjN16k2Rqiw==
"""
    // printf "The true sign of intelligence is not knowledge but imagination." | openssl rsautl -encrypt -oaep -pubin -inkey bob.pub.pem -out >(base64)
    let cipherTextWithBobKeyBase64OAEP = """
NbydryFPK1o8NBzEdllwnJYCokNY5O9rXvM0cSNVKdmrkDk/Uz4NsCY737QdxDsPTCllQct+w+vZEkhgxN6bfwZJqvgj4R8sqSVMRJTsQeQuEUuAShQu5bG\
z6TFibK1hr3x6fiS4rhX5KX+e+ByCiEo/xcE5xM9CeBM1dbagJsNZtSNquqyaWQwlXD16HsUTWcUX3urfO3JjPCr5lQnDlXPn8EJDY+UMELDrm3fVk6anOV\
Fr1AEs3Xe3hoWWZx6U0aregC2kZJvJJh4JZAyxJFb/+/lTtUIq5xr8RqZ+KXao8blz9puqYSUGNZ2uXVGauSEz/fn4oi2mG/q2vk0zgA==
"""

    let defaultDecryptionError_RSA1_5 = RSAError.decryptingFailed(description: "The operation couldn’t be completed. (OSStatus error -50 - RSAdecrypt wrong input (err -1))")
    let defaultDecryptionError_RSAOAEP = RSAError.decryptingFailed(description: "The operation couldn’t be completed. (OSStatus error -50 - RSAdecrypt wrong input (err 26))")

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testDecryptingWithAliceKey_RSA1_5() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)
        let decryptedData = try! decrypter.decrypt(Data(base64Encoded: cipherTextWithAliceKeyBase64)!)
        let decryptedMessage = String(data: decryptedData, encoding: String.Encoding.utf8)

        XCTAssertEqual(decryptedMessage, message)
    }

    func testDecryptingWithAliceKey_RSAOAEP() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSAOAEP, privateKey: privateKeyAlice2048!)
        let decryptedData = try! decrypter.decrypt(Data(base64Encoded: cipherTextWithAliceKeyBase64OAEP)!)
        let decryptedMessage = String(data: decryptedData, encoding: String.Encoding.utf8)

        XCTAssertEqual(decryptedMessage, message)
    }

    func testDecryptingWithBobKey_RSA1_5() {
        guard privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyBob2048!)
        let decryptedData = try! decrypter.decrypt(Data(base64URLEncoded: cipherTextWithBobKeyBase64)!)
        let decryptedMessage = String(data: decryptedData, encoding: String.Encoding.utf8)

        XCTAssertEqual(decryptedMessage, message)
    }

    func testDecryptingWithBobKey_RSAOAEP() {
        guard privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSAOAEP, privateKey: privateKeyBob2048!)
        let decryptedData = try! decrypter.decrypt(Data(base64URLEncoded: cipherTextWithBobKeyBase64OAEP)!)
        let decryptedMessage = String(data: decryptedData, encoding: String.Encoding.utf8)

        XCTAssertEqual(decryptedMessage, message)
    }

    func testDecryptingAliceSecretWithBobKey_RSA1_5() {
        guard privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyBob2048!)

        // Decrypting with the wrong key should throw an error
        XCTAssertThrowsError(try decrypter.decrypt(Data(base64URLEncoded: cipherTextWithAliceKeyBase64)!)) { (error: Error) in
            XCTAssertEqual(error as! RSAError, defaultDecryptionError_RSA1_5)
        }
    }

    func testDecryptingAliceSecretWithBobKey_RSAOAEP() {
        guard privateKeyBob2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSAOAEP, privateKey: privateKeyBob2048!)

        // Decrypting with the wrong key should throw an error
        XCTAssertThrowsError(try decrypter.decrypt(Data(base64URLEncoded: cipherTextWithAliceKeyBase64OAEP)!)) { (error: Error) in
            XCTAssertEqual(error as! RSAError, defaultDecryptionError_RSAOAEP)
        }
    }

    func testDecryptingBobSecretWithAliceKey_RSA1_5() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)

        // Decrypting with the wrong key should throw an error
        XCTAssertThrowsError(try decrypter.decrypt(Data(base64URLEncoded: cipherTextWithBobKeyBase64)!)) { (error: Error) in
            XCTAssertEqual(error as! RSAError, defaultDecryptionError_RSA1_5)
        }
    }

    func testDecryptingBobSecretWithAliceKey_RSAOAEP() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSAOAEP, privateKey: privateKeyAlice2048!)

        // Decrypting with the wrong key should throw an error
        XCTAssertThrowsError(try decrypter.decrypt(Data(base64URLEncoded: cipherTextWithBobKeyBase64OAEP)!)) { (error: Error) in
            XCTAssertEqual(error as! RSAError, defaultDecryptionError_RSAOAEP)
        }
    }

    func testCipherTextLengthTooLong_RSA1_5() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)
        XCTAssertThrowsError(try decrypter.decrypt(Data(count: 300))) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

    func testCipherTextLengthTooLong_RSAOAEP() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSAOAEP, privateKey: privateKeyAlice2048!)
        XCTAssertThrowsError(try decrypter.decrypt(Data(count: 300))) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

    func testCipherTextLengthZero_RSA1_5() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)
        XCTAssertThrowsError(try decrypter.decrypt(Data(count: 0))) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

    func testCipherTextLengthZero_RSAOAEP() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSAOAEP, privateKey: privateKeyAlice2048!)
        XCTAssertThrowsError(try decrypter.decrypt(Data(count: 0))) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

    func testCipherTextLengthExactlyRight_RSA1_5() {
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

    func testCipherTextLengthExactlyRight_RSAOAEP() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        // For detailed information about the allowed cipher length for RSAOAEP,
        // please refer to the RFC(https://tools.ietf.org/html/rfc3447#section-7.1.2
        // https://tools.ietf.org/html/rfc3174#section-1,
        // and https://www.rfc-editor.org/errata_search.php?rfc=3447)
        // C: ciphertext to be decrypted, an octet string of length k, where k >= 2hLen + 2
        let cipherTextLengthInBytes = SecKeyGetBlockSize(privateKeyAlice2048!)
        let testMessage = Data(count: cipherTextLengthInBytes)

        let decrypter = RSADecrypter(algorithm: .RSA1_5, privateKey: privateKeyAlice2048!)

        XCTAssertThrowsError(try decrypter.decrypt(testMessage)) { (error: Error) in
            // Should throw "decryption failed", but
            // should _not_ throw cipherTextLenghtNotSatisfied
            XCTAssertNotEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

    func testCipherTextLengthTooLongByOneByte_RSA1_5() {
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

    func testCipherTextLengthTooLongByOneByte_RSAOAEP() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let cipherTextLengthInBytes = SecKeyGetBlockSize(privateKeyAlice2048!)
        let testMessage = Data(count: cipherTextLengthInBytes + 1)

        let decrypter = RSADecrypter(algorithm: .RSAOAEP, privateKey: privateKeyAlice2048!)
        XCTAssertThrowsError(try decrypter.decrypt(testMessage)) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

    func testCipherTextLengthTooShortByOneByte_RSA1_5() {
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

    func testCipherTextLengthTooShortByOneByte_RSAOAEP() {
        guard privateKeyAlice2048 != nil else {
            XCTFail()
            return
        }

        let cipherTextLengthInBytes = SecKeyGetBlockSize(privateKeyAlice2048!)
        let testMessage = Data(count: cipherTextLengthInBytes - 1)

        let decrypter = RSADecrypter(algorithm: .RSAOAEP, privateKey: privateKeyAlice2048!)
        XCTAssertThrowsError(try decrypter.decrypt(testMessage)) { (error: Error) in
            XCTAssertEqual(error as? RSAError, RSAError.cipherTextLenghtNotSatisfied)
        }
    }

}
