//
//  JWETests.swift
//  Tests
//
//  Created by Carol Capek on 31.10.17.
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

class JWETests: CryptoTestCase {

     let compactSerializedJWE = """
        eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.Od5AMgOHu6rcEYWkX7w_x_wnMlM5JfZaszCC4xtLGYU9d0BnPm95UWUrgSh\
        StGH6LHMxpGdru6gXpdxfhhrji12vUIzmkbyNW5M9wjx2t0e4pzzBSYxgOzFoa3jT9a0PcZfyqHIeTrcrTHtpSJ_CIDiZ3MIeqA7hjuRqu2YcTA\
        E0v5TPLhHDVRBptkOggA5SL2-gRuUuYoWdanMw_JTHK4utXQZoSY1LTdub_Fh5ez1RqOouc3an5Hx6ImzyJS_cbO_l9xHpHjE7in6SeV9bAZTaY\
        EaGnjGKEVaGQ7JiwtTA5rDfVQ5RHSn6blB2Hh5Am7mKzssYu9JjUmr3T-ez_g.M6QnlRxQQ5YS2rF4-wwT3g.4GAtq6fJWJt249SEuK5P_3xJGN\
        YP_e_rhz0PVg9QnJXiRl030ggI9GGs3E_0pEPBs9_WJ3E60qQVoXTIMbJXSQ.bQc-W1Ph_0_3kX570pT8gjDlGyiK3kF8PlHiT7GWfMo
        """.data(using: .utf8)!

    let plaintext = """
        The true sign of intelligence is not knowledge but imagination.
        """.data(using: .utf8)!

    func testJWERoundtrip() {
        let header = JWEHeader(algorithm: .RSA1_5, encryptionAlgorithm: .A256CBCHS512)
        let payload = Payload(message.data(using: .utf8)!)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .RSA1_5, encryptionKey: publicKey2048!, contentEncyptionAlgorithm: .A256CBCHS512)!
        let jweEnc = try! JWE(header: header, payload: payload, encrypter: encrypter)

        let jweDec = try! JWE(compactSerialization: jweEnc.compactSerializedData)
        let decryptedPayload = try! jweDec.decrypt(with: privateKey2048!)

        XCTAssertEqual(message.data(using: .utf8)!, decryptedPayload.data())
    }

    func testDecryptWithInferredDecrypter() {
        let jwe = try! JWE(compactSerialization: compactSerializedJWE)

        XCTAssertEqual(try! jwe.decrypt(with: privateKey2048!).data(), plaintext)
    }

    func testDecryptFails() {
        let header = JWEHeader(algorithm: .RSA1_5, encryptionAlgorithm: .A256CBCHS512)
        let payload = Payload(message.data(using: .utf8)!)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .RSA1_5, encryptionKey: publicKey2048!, contentEncyptionAlgorithm: .A256CBCHS512)!
        let jweEnc = try! JWE(header: header, payload: payload, encrypter: encrypter)

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrApplicationTag as String: privateKey2048Tag
            ]
        ]

        var error: Unmanaged<CFError>?

        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print(error!)
            return
        }

        let jweDec = try! JWE(compactSerialization: jweEnc.compactSerializedData)

        XCTAssertThrowsError(try jweDec.decrypt(with: key))
    }

    func testDecryptWithExplicitDecrypter() {
        let jwe = try! JWE(compactSerialization: compactSerializedJWE)

        let decrypter = Decrypter(
            keyDecryptionAlgorithm: .RSA1_5,
            decryptionKey: privateKey2048!,
            contentDecryptionAlgorithm: .A256CBCHS512
        )!

        XCTAssertEqual(try! jwe.decrypt(using: decrypter).data(), plaintext)
    }

    func testDecryptWithExplicitDecrypterWrongAlgInHeader() {
        // Replaces alg "RSA1_5" with alg "RSA-OAEP" in header
        let malformedSerialization = String(data: compactSerializedJWE, encoding: .utf8)!.replacingOccurrences(
            of: "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0",
            with: "eyJhbGciOiAiUlNBLU9BRVAiLCJlbmMiOiAiQTI1NkNCQy1IUzUxMiJ9"
        ).data(using: .utf8)!

        let jwe = try! JWE(compactSerialization: malformedSerialization)

        let decrypter = Decrypter(
            keyDecryptionAlgorithm: .RSA1_5,
            decryptionKey: privateKey2048!,
            contentDecryptionAlgorithm: .A256CBCHS512
        )!

        XCTAssertThrowsError(try jwe.decrypt(using: decrypter), "decrypting with wrong header alg") { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.decryptingFailed(description: "JWE header algorithms do not match encrypter algorithms."))
        }
    }

    func testDecryptWithExplicitDecrypterWrongEncInHeader() {
        // Replaces alg "A256CBC-HS512" with alg "A128GCM" in header
        let malformedSerialization = String(data: compactSerializedJWE, encoding: .utf8)!.replacingOccurrences(
            of: "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0",
            with: "eyJhbGciOiAiUlNBMV81IiwiZW5jIjogIkExMjhHQ00ifQ"
            ).data(using: .utf8)!

        let jwe = try! JWE(compactSerialization: malformedSerialization)

        let decrypter = Decrypter(
            keyDecryptionAlgorithm: .RSA1_5,
            decryptionKey: privateKey2048!,
            contentDecryptionAlgorithm: .A256CBCHS512
        )!

        XCTAssertThrowsError(try jwe.decrypt(using: decrypter), "decrypting with wrong header alg") { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.decryptingFailed(description: "JWE header algorithms do not match encrypter algorithms."))
        }
    }

    func testDecryptWithExplicitDecrypterFailsForKey() {
        let jwe = try! JWE(compactSerialization: compactSerializedJWE)

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrApplicationTag as String: privateKey2048Tag
            ]
        ]

        var error: Unmanaged<CFError>?

        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print(error!)
            return
        }

        let decrypter = Decrypter(
            keyDecryptionAlgorithm: .RSA1_5,
            decryptionKey: key,
            contentDecryptionAlgorithm: .A256CBCHS512
        )!

        XCTAssertThrowsError(try jwe.decrypt(using: decrypter))
    }

}
