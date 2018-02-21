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
@testable import SwiftJOSE

class JWETests: CryptoTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testJWERoundtrip() {
        let header = JWEHeader(algorithm: .RSA1_5, encryptionAlgorithm: .A256CBCHS512)
        let payload = Payload(message.data(using: .utf8)!)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .RSA1_5, keyEncryptionKey: publicKey2048!, contentEncyptionAlgorithm: .A256CBCHS512)
        let jweEnc = JWE(header: header, payload: payload, encrypter: encrypter)!

        let jweDec = try! JWE(compactSerialization: jweEnc.compactSerializedData)
        let decryptedPayload = jweDec.decrypt(with: privateKey2048!)

        XCTAssertEqual(message.data(using: .utf8)!, decryptedPayload?.data())
    }

    func testDecrypt() {
        let compactSerializedJWE = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.Od5AMgOHu6rcEYWkX7w_x_wnMlM5JfZaszCC4xtLGYU9d0BnPm95UWUrgShStGH6LHMxpGdru6gXpdxfhhrji12vUIzmkbyNW5M9wjx2t0e4pzzBSYxgOzFoa3jT9a0PcZfyqHIeTrcrTHtpSJ_CIDiZ3MIeqA7hjuRqu2YcTAE0v5TPLhHDVRBptkOggA5SL2-gRuUuYoWdanMw_JTHK4utXQZoSY1LTdub_Fh5ez1RqOouc3an5Hx6ImzyJS_cbO_l9xHpHjE7in6SeV9bAZTaYEaGnjGKEVaGQ7JiwtTA5rDfVQ5RHSn6blB2Hh5Am7mKzssYu9JjUmr3T-ez_g.M6QnlRxQQ5YS2rF4-wwT3g.4GAtq6fJWJt249SEuK5P_3xJGNYP_e_rhz0PVg9QnJXiRl030ggI9GGs3E_0pEPBs9_WJ3E60qQVoXTIMbJXSQ.bQc-W1Ph_0_3kX570pT8gjDlGyiK3kF8PlHiT7GWfMo"
        let jwe = try! JWE(compactSerialization: compactSerializedJWE)
        let payloadString = String(data: (jwe.decrypt(with: privateKey2048!)!).data(), encoding: .utf8)!

        XCTAssertEqual(payloadString, "The true sign of intelligence is not knowledge but imagination.")
    }

    func testDecryptFails() {
        let header = JWEHeader(algorithm: .RSA1_5, encryptionAlgorithm: .A256CBCHS512)
        let payload = Payload(message.data(using: .utf8)!)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .RSA1_5, keyEncryptionKey: publicKey2048!, contentEncyptionAlgorithm: .A256CBCHS512)
        let jweEnc = JWE(header: header, payload: payload, encrypter: encrypter)!

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

        XCTAssertNil(jweDec.decrypt(with: key))
    }
}
