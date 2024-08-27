// swiftlint:disable force_unwrapping
//
//  JWERSATests.swift
//  Tests
//
//  Created by Carol Capek on 31.10.17.
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

class JWERSATests: RSACryptoTestCase {
    let keyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.RSA1_5, .RSAOAEP, .RSAOAEP256]

    // The JWE serializations below are generated using the Java library Nimbus JOSE + JWT.
    // The key used to encrypt the JWEs in Nimbus is the JWK representation of `publicKeyAlice2048`.
    // That way we can decrypt them using the corresponding `privateKeyAlice2048`.
    //
    // To generate the serializations, setup a Maven project according to https://connect2id.com/products/nimbus-jose-jwt.
    // Then use the following code to print out serializations:
    //
    // JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, com.nimbusds.jose.EncryptionMethod.A256CBC_HS512);
    //
    // Payload payload = new Payload("The true sign of intelligence is not knowledge but imagination.");
    //
    // JWEObject jwe = new JWEObject(header, payload);
    //
    // Base64URL n = new Base64URL("<Insert modulus of public key here (can be obtained by converting it to a JWK)>");
    // Base64URL e = new Base64URL("<Insert public exponent of public key here (can be obtained by converting it to a JWK)>");
    // RSAKey jwk = new RSAKey(n, e, null, null, null, null, null, null, null, null, null);
    //
    // RSAEncrypter encrypter = new RSAEncrypter(jwk);
    //
    // jwe.encrypt(encrypter);
    //
    // System.out.println(jwe.serialize());

    let compactSerializedJWERSHA1 = """
        eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.Od5AMgOHu6rcEYWkX7w_x_wnMlM5JfZaszCC4xtLGYU9d0BnPm95UWUrgSh\
        StGH6LHMxpGdru6gXpdxfhhrji12vUIzmkbyNW5M9wjx2t0e4pzzBSYxgOzFoa3jT9a0PcZfyqHIeTrcrTHtpSJ_CIDiZ3MIeqA7hjuRqu2YcTA\
        E0v5TPLhHDVRBptkOggA5SL2-gRuUuYoWdanMw_JTHK4utXQZoSY1LTdub_Fh5ez1RqOouc3an5Hx6ImzyJS_cbO_l9xHpHjE7in6SeV9bAZTaY\
        EaGnjGKEVaGQ7JiwtTA5rDfVQ5RHSn6blB2Hh5Am7mKzssYu9JjUmr3T-ez_g.M6QnlRxQQ5YS2rF4-wwT3g.4GAtq6fJWJt249SEuK5P_3xJGN\
        YP_e_rhz0PVg9QnJXiRl030ggI9GGs3E_0pEPBs9_WJ3E60qQVoXTIMbJXSQ.bQc-W1Ph_0_3kX570pT8gjDlGyiK3kF8PlHiT7GWfMo
        """.data(using: .utf8)!

    let compactSerializedJWERSAOAEPSHA1 = """
        eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAifQ.VjoovzQfSQ9zRbPxFR-7suNJesM9yVQrH7tqvEWospcIuYBSQjPTBE6j\
        m32iqx9YQd3LiCLqDwz9fzn6_FANSGAYrVgibYX0BqCzN_l83t7YWIa_h43TCgE4sRestYasbqwXY-EfLNK2u37tRxCxxLKDtyugujxNZyQxpOh\
        gEA0TzJwwPa2ITX37Z0zF_sAEp_09lF0jWm9u4cVSt-mIIYcpgh5c3sIw1IWs7ynPNWn9Y68YmXJhgeZkIzDiLNGhf3KesH9to4z-EvIyXVBIWl\
        edDnI6qUShAtcvkFctCqRbxIwIVGfuy1Mr1DBx6564Pe3i96V2jqW9b98svcVyQQ.dXU-3Hw7_IY5OC46PBLj3A.4WBT8JS5c7P5iSoME8U0wkl\
        DAnkrZOVxFIvWyCZ5bd1gLLAtrNynfos1dS8lZaMBuaB8qFVxeASG93WpTGcM3Q.BQIMElwgzx7ytiikieuxxRTjrzA8dvr8MpQIF27oH2o
        """.data(using: .utf8)!

    let compactSerializedJWERSAOAEPSHA256 = """
        eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.U1gJUJ81kHBO02JbjsPXOu0sbbV38R87jTzc4SHPs3BcFjzrTSd\
        ECN6sqcNQ-Yq_Z9-aO0Xjs_plCxY3ICWt066bDqSYPIHtSPP-dZ_UMoJb6yHZNkBQqv-_pONL_p4kUTVfEpfxtkDvl2qojOS04aFdKSDv6Pr5jo\
        YlV266u9p-qdbaaEk2B3yihbaenXUnJKU-uJJN_zRYPX5slFWR9ahYEniw-xV4CT6guVgZu8MdZuzSm_HRu4PS5SzH3sc7lvk50rXRL-ivHC2bX\
        WlJJlHwsgGiQiln7VxKx7-NrCpRiWGv0lrz41YKtMXO7iqStLozmYl-FoM37C03XDQyJw.5kuCqSzPQ79yxN4SkWbVTg.kosTf8K4SIX2cgibmC\
        z8ONRqnbRk8OhF79pAKmid7C6oTXmVRl-anwQYN8KP_1aUGOIzYaZnZEHufsm6F9BTRA.eeuVZVDX-zSiikfD4Np6LiPNuC12zRvtgVc6NbcHo4Q
        """.data(using: .utf8)!

    lazy var compactSerializedData: [String: Data] = {
        [
            KeyManagementAlgorithm.RSA1_5.rawValue: compactSerializedJWERSHA1,
            KeyManagementAlgorithm.RSAOAEP.rawValue: compactSerializedJWERSAOAEPSHA1,
            KeyManagementAlgorithm.RSAOAEP256.rawValue: compactSerializedJWERSAOAEPSHA256
        ]
    }()

    let plaintext = """
        The true sign of intelligence is not knowledge but imagination.
        """.data(using: .utf8)!

    func testJWERoundtrip() {
        guard let publicKeyAlice2048 = publicKeyAlice2048  else {
            XCTFail("publicKeyAlice2048 was nil.")
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512)
            let payload = Payload(message.data(using: .utf8)!)
            let encrypter = Encrypter(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: publicKeyAlice2048)!
            let decrypter = Decrypter(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512, decryptionKey: privateKeyAlice2048!)!
            let jweEnc = try! JWE(header: header, payload: payload, encrypter: encrypter)
            let jweDec = try! JWE(compactSerialization: jweEnc.compactSerializedData)
            let decryptedPayload = try! jweDec.decrypt(using: decrypter)

            XCTAssertEqual(message.data(using: .utf8)!, decryptedPayload.data())
        }
    }

    func testJWEEncryptionWithMismatchingHeaderAlg() {
        guard let publicKeyAlice2048 = publicKeyAlice2048  else {
            XCTFail("publicKeyAlice2048 was nil.")
            return
        }

        let header = JWEHeader(keyManagementAlgorithm: .RSA1_5, contentEncryptionAlgorithm: .A256CBCHS512)
        let payload = Payload(message.data(using: .utf8)!)
        let encrypter = Encrypter(keyManagementAlgorithm: .RSAOAEP, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: publicKeyAlice2048)!

        XCTAssertThrowsError(try JWE(header: header, payload: payload, encrypter: encrypter))
    }

    func testJWEEncryptionWithMismatchingHeaderEnc() {
        guard let publicKeyAlice2048 = publicKeyAlice2048  else {
            XCTFail("publicKeyAlice2048 was nil.")
            return
        }

        let header = JWEHeader(keyManagementAlgorithm: .RSA1_5, contentEncryptionAlgorithm: .A128CBCHS256)
        let payload = Payload(message.data(using: .utf8)!)
        let encrypter = Encrypter(keyManagementAlgorithm: .RSA1_5, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: publicKeyAlice2048)!

        XCTAssertThrowsError(try JWE(header: header, payload: payload, encrypter: encrypter))
    }

    func testJWERoundtripWithNonRequiredJWEHeaderParameter() {
        for algorithm in keyManagementModeAlgorithms {
            var header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512)
            header.kid = "kid"

            let payload = Payload(message.data(using: .utf8)!)
            let encrypter = Encrypter(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: publicKeyAlice2048!)!
            let decrypter = Decrypter(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512, decryptionKey: privateKeyAlice2048!)!

            let jweEnc = try! JWE(header: header, payload: payload, encrypter: encrypter)
            let jweDec = try! JWE(compactSerialization: jweEnc.compactSerializedData)
            let decryptedPayload = try! jweDec.decrypt(using: decrypter)

            XCTAssertEqual(message.data(using: .utf8)!, decryptedPayload.data())
        }
    }

    func testDecryptFails() {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrApplicationTag as String: privateKeyAlice2048Tag
            ]
        ]

        for algorithm in keyManagementModeAlgorithms {
            let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512)
            let payload = Payload(message.data(using: .utf8)!)
            let encrypter = Encrypter(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: publicKeyAlice2048!)!
            let jweEnc = try! JWE(header: header, payload: payload, encrypter: encrypter)

            var error: Unmanaged<CFError>?

            guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                print(error!)
                return
            }

            let jweDec = try! JWE(compactSerialization: jweEnc.compactSerializedData)
            let decrypter = Decrypter(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: .A256CBCHS512, decryptionKey: key)!

            XCTAssertThrowsError(try jweDec.decrypt(using: decrypter))
        }
    }

    func testDecryptWithExplicitDecrypter() {
        guard let privateKeyAlice2048 = privateKeyAlice2048  else {
            XCTFail("privateKeyAlice2048 was nil.")
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            let jwe = try! JWE(compactSerialization: compactSerializedData[algorithm.rawValue]!)

            let decrypter = Decrypter(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A256CBCHS512,
                decryptionKey: privateKeyAlice2048
            )!

            XCTAssertEqual(try! jwe.decrypt(using: decrypter).data(), plaintext)
        }
    }

    func testDecryptWithExplicitDecrypterWrongAlgInHeaderRSA1_5() {
        // Replaces alg "RSA1_5" with alg "RSA-OAEP" in header
        let malformedSerialization = String(data: compactSerializedData[KeyManagementAlgorithm.RSA1_5.rawValue]!, encoding: .utf8)!.replacingOccurrences(
            of: "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0",
            with: "eyJhbGciOiAiUlNBLU9BRVAiLCJlbmMiOiAiQTI1NkNCQy1IUzUxMiJ9"
            ).data(using: .utf8)!

        let jwe = try! JWE(compactSerialization: malformedSerialization)

        let decrypter = Decrypter(
            keyManagementAlgorithm: .RSA1_5,
            contentEncryptionAlgorithm: .A256CBCHS512,
            decryptionKey: privateKeyAlice2048!
        )!

        XCTAssertThrowsError(try jwe.decrypt(using: decrypter), "decrypting with wrong alg in header") { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.keyManagementAlgorithmMismatch)
        }
    }

    func testDecryptWithExplicitDecrypterWrongAlgInHeaderRSAOAEPSHA256() {
        // Replaces alg "RSA-OAEP-256" with alg "RSA-OAEP" in header
        let malformedSerialization = String(data: compactSerializedData[KeyManagementAlgorithm.RSAOAEP256.rawValue]!, encoding: .utf8)!.replacingOccurrences(
            of: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0",
            with: "eyJhbGciOiAiUlNBLU9BRVAiLCJlbmMiOiAiQTI1NkNCQy1IUzUxMiJ9"
            ).data(using: .utf8)!

        let jwe = try! JWE(compactSerialization: malformedSerialization)

        let decrypter = Decrypter(
            keyManagementAlgorithm: .RSAOAEP256,
            contentEncryptionAlgorithm: .A256CBCHS512,
            decryptionKey: privateKeyAlice2048!
        )!

        XCTAssertThrowsError(try jwe.decrypt(using: decrypter), "decrypting with wrong alg in header with RSA-OAEP-256 algorithm") { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.keyManagementAlgorithmMismatch)
        }
    }

    func testDecryptWithExplicitDecrypterWrongEncInHeaderA256CBC() {
        // Replaces enc "A256CBC-HS512" with enc "A128GCM" in header
        let malformedSerialization = String(data: compactSerializedData[KeyManagementAlgorithm.RSA1_5.rawValue]!, encoding: .utf8)!.replacingOccurrences(
            of: "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0",
            with: "eyJhbGciOiAiUlNBMV81IiwiZW5jIjogIkExMjhHQ00ifQ"
        ).data(using: .utf8)!

        let jwe = try! JWE(compactSerialization: malformedSerialization)

        let decrypter = Decrypter(
            keyManagementAlgorithm: .RSA1_5,
            contentEncryptionAlgorithm: .A256CBCHS512,
            decryptionKey: privateKeyAlice2048!
        )!

        XCTAssertThrowsError(try jwe.decrypt(using: decrypter), "decrypting with wrong enc in header") { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.contentEncryptionAlgorithmMismatch)
        }
    }

    func testDecryptWithExplicitDecrypterFailsForWrongKey() {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]

        var error: Unmanaged<CFError>?

        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print(error!)
            return
        }

        for algorithm in keyManagementModeAlgorithms {
            let jwe = try! JWE(compactSerialization: compactSerializedData[algorithm.rawValue]!)

            let decrypter = Decrypter(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A256CBCHS512,
                decryptionKey: key
            )!

            XCTAssertThrowsError(try jwe.decrypt(using: decrypter))
       }
    }

}
// swiftlint:enable force_unwrapping
