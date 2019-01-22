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

class JWETests: RSACryptoTestCase {

    let compactSerializedJWERSA1 = """
        eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.Od5AMgOHu6rcEYWkX7w_x_wnMlM5JfZaszCC4xtLGYU9d0BnPm95UWUrgSh\
        StGH6LHMxpGdru6gXpdxfhhrji12vUIzmkbyNW5M9wjx2t0e4pzzBSYxgOzFoa3jT9a0PcZfyqHIeTrcrTHtpSJ_CIDiZ3MIeqA7hjuRqu2YcTA\
        E0v5TPLhHDVRBptkOggA5SL2-gRuUuYoWdanMw_JTHK4utXQZoSY1LTdub_Fh5ez1RqOouc3an5Hx6ImzyJS_cbO_l9xHpHjE7in6SeV9bAZTaY\
        EaGnjGKEVaGQ7JiwtTA5rDfVQ5RHSn6blB2Hh5Am7mKzssYu9JjUmr3T-ez_g.M6QnlRxQQ5YS2rF4-wwT3g.4GAtq6fJWJt249SEuK5P_3xJGN\
        YP_e_rhz0PVg9QnJXiRl030ggI9GGs3E_0pEPBs9_WJ3E60qQVoXTIMbJXSQ.bQc-W1Ph_0_3kX570pT8gjDlGyiK3kF8PlHiT7GWfMo
        """.data(using: .utf8)!

    let compactSerializedJWERSAOAEPSHA256 = "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.RL7Ny2UFhgp04E_sJnnX77slkDM8X9LETqFAn3WpL_D6pXSYE9pUJK8DYFETi2FzANVqz128wzySW2tzVxltDfxi9irInmK0W0nls4aFRqpPUL2xG_izW624y-J5QebsjEUQg-RdbnHz82VO9OrvJVGst8HFQn0XsCN76WGgZcPfON3As5dfIyUctW3twCWB_G4lWZqmvOJ4GqkT3SpMc3aQtGzKdJ0WN-4MKbm0Shk-07um8yJgzH6xaLHcbJHhWjDB6VHBkiX6X7bbLiN_R_XQKO78Nlj2LFn5OO2B5VoINH_DZj6UsEuSywTHTl7ET-QgXYbsLTrXB2Pzs3gpvQ.L9MZP9n4UKljKgGEoEnbyA.8uZpYsF9pNIQy06zCoWv7gBNW6DC0-KwWUXpiGcFfVhyBD1hfQC7bQD1fH6GeargKBNjrYcv7bm_5purQFTt_A.ecd44cJE0BH4Fwqm2fDHM1dXhHtiFDJn2VEhw55VP28".data(using: .utf8)!

    lazy var compactSerializedData: [String: Data] = {
        [AsymmetricKeyAlgorithm.RSA1_5.rawValue: compactSerializedJWERSA1,
         AsymmetricKeyAlgorithm.RSAOAEP256.rawValue: compactSerializedJWERSAOAEPSHA256]
    }()

    let plaintext = """
        The true sign of intelligence is not knowledge but imagination.
        """.data(using: .utf8)!

    @available(*, deprecated)
    func testJWERoundtrip() {
        guard let publicKeyAlice2048 = publicKeyAlice2048  else {
            XCTFail("publicKeyAlice2048 was nil.")
            return
        }

        for algorithm in AsymmetricKeyAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }
            
            let header = JWEHeader(algorithm: algorithm, encryptionAlgorithm: .A256CBCHS512)
            let payload = Payload(message.data(using: .utf8)!)
            let encrypter = Encrypter(keyEncryptionAlgorithm: algorithm, encryptionKey: publicKeyAlice2048, contentEncyptionAlgorithm: .A256CBCHS512)!
            let jweEnc = try! JWE(header: header, payload: payload, encrypter: encrypter)
            let jweDec = try! JWE(compactSerialization: jweEnc.compactSerializedData)
            let decryptedPayload = try! jweDec.decrypt(with: privateKeyAlice2048!)
            
            XCTAssertEqual(message.data(using: .utf8)!, decryptedPayload.data())
        }
    }

    @available(*, deprecated)
    func testJWERoundtripWithNonRequiredJWEHeaderParameter() {
        for algorithm in AsymmetricKeyAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }
            
            var header = JWEHeader(algorithm: algorithm, encryptionAlgorithm: .A256CBCHS512)
            header.kid = "kid"
            
            let payload = Payload(message.data(using: .utf8)!)
            let encrypter = Encrypter(keyEncryptionAlgorithm: algorithm, encryptionKey: publicKeyAlice2048!, contentEncyptionAlgorithm: .A256CBCHS512)!
            let jweEnc = try! JWE(header: header, payload: payload, encrypter: encrypter)
            
            let jweDec = try! JWE(compactSerialization: jweEnc.compactSerializedData)
            let decryptedPayload = try! jweDec.decrypt(with: privateKeyAlice2048!)
            
            XCTAssertEqual(message.data(using: .utf8)!, decryptedPayload.data())
        }
    }

    @available(*, deprecated)
    func testDecryptWithInferredDecrypter() {
        guard let privateKeyAlice2048 = privateKeyAlice2048  else {
            XCTFail("privateKeyAlice2048 was nil.")
            return
        }
        for algorithm in AsymmetricKeyAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }
            
            let jwe = try! JWE(compactSerialization: compactSerializedData[algorithm.rawValue]!)
            let payload = try! jwe.decrypt(with: privateKeyAlice2048).data()
            
            XCTAssertEqual(payload, plaintext)
        }
    }

    @available(*, deprecated)
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

        for algorithm in AsymmetricKeyAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }
            
            let header = JWEHeader(algorithm: algorithm, encryptionAlgorithm: .A256CBCHS512)
            let payload = Payload(message.data(using: .utf8)!)
            let encrypter = Encrypter(keyEncryptionAlgorithm: algorithm, encryptionKey: publicKeyAlice2048!, contentEncyptionAlgorithm: .A256CBCHS512)!
            let jweEnc = try! JWE(header: header, payload: payload, encrypter: encrypter)
            
            var error: Unmanaged<CFError>?
            
            guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                print(error!)
                return
            }
            
            let jweDec = try! JWE(compactSerialization: jweEnc.compactSerializedData)
            
            XCTAssertThrowsError(try jweDec.decrypt(with: key))
        }
    }

    func testDecryptWithExplicitDecrypter() {
        guard let privateKeyAlice2048 = privateKeyAlice2048  else {
            XCTFail("privateKeyAlice2048 was nil.")
            return
        }

        for algorithm in AsymmetricKeyAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }
            
            let jwe = try! JWE(compactSerialization: compactSerializedData[algorithm.rawValue]!)
            
            let decrypter = Decrypter(
                keyDecryptionAlgorithm: algorithm,
                decryptionKey: privateKeyAlice2048,
                contentDecryptionAlgorithm: .A256CBCHS512
                )!
            
            XCTAssertEqual(try! jwe.decrypt(using: decrypter).data(), plaintext)
        }
    }

    func testDecryptWithExplicitDecrypterWrongAlgInHeader() {
        // Replaces alg "RSA1_5" with alg "RSA-OAEP" in header
        let malformedSerialization = String(data: compactSerializedData[AsymmetricKeyAlgorithm.RSA1_5.rawValue]!, encoding: .utf8)!.replacingOccurrences(
            of: "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0",
            with: "eyJhbGciOiAiUlNBLU9BRVAiLCJlbmMiOiAiQTI1NkNCQy1IUzUxMiJ9"
            ).data(using: .utf8)!

        let jwe = try! JWE(compactSerialization: malformedSerialization)

        let decrypter = Decrypter(
            keyDecryptionAlgorithm: .RSA1_5,
            decryptionKey: privateKeyAlice2048!,
            contentDecryptionAlgorithm: .A256CBCHS512
            )!

        XCTAssertThrowsError(try jwe.decrypt(using: decrypter), "decrypting with wrong alg in header") { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.decryptingFailed(description: "JWE header algorithms do not match encrypter algorithms."))
        }
    }

    func testDecryptWithExplicitDecrypterWrongAlgInHeaderRSAOAEPSHA256() {
        // Replaces alg "RSA-OAEP-256" with alg "RSA-OAEP" in header
        let malformedSerialization = String(data: compactSerializedData[AsymmetricKeyAlgorithm.RSAOAEP256.rawValue]!, encoding: .utf8)!.replacingOccurrences(
            of: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0",
            with: "eyJhbGciOiAiUlNBLU9BRVAiLCJlbmMiOiAiQTI1NkNCQy1IUzUxMiJ9"
            ).data(using: .utf8)!
        
        let jwe = try! JWE(compactSerialization: malformedSerialization)
        
        let decrypter = Decrypter(
            keyDecryptionAlgorithm: .RSAOAEP256,
            decryptionKey: privateKeyAlice2048!,
            contentDecryptionAlgorithm: .A256CBCHS512
            )!
        
        XCTAssertThrowsError(try jwe.decrypt(using: decrypter), "decrypting with wrong alg in header with RSA-OAEP-256 algorithm") { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.decryptingFailed(description: "JWE header algorithms do not match encrypter algorithms."))
        }
    }

    func testDecryptWithExplicitDecrypterWrongEncInHeader() {
        // Replaces enc "A256CBC-HS512" with enc "A128GCM" in header
        let malformedSerialization = String(data: compactSerializedData[AsymmetricKeyAlgorithm.RSA1_5.rawValue]!, encoding: .utf8)!.replacingOccurrences(
            of: "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0",
            with: "eyJhbGciOiAiUlNBMV81IiwiZW5jIjogIkExMjhHQ00ifQ"
            ).data(using: .utf8)!

        let jwe = try! JWE(compactSerialization: malformedSerialization)

        let decrypter = Decrypter(
            keyDecryptionAlgorithm: .RSA1_5,
            decryptionKey: privateKeyAlice2048!,
            contentDecryptionAlgorithm: .A256CBCHS512
            )!

        XCTAssertThrowsError(try jwe.decrypt(using: decrypter), "decrypting with wrong enc in header") { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.decryptingFailed(description: "JWE header algorithms do not match encrypter algorithms."))
        }
    }

    func testDecryptWithExplicitDecrypterWrongEncInHeaderRSAOAEPSHA256() {
        // Replaces enc "A256CBC-HS512" with enc "A128GCM" in header
        let malformedSerialization = String(data: compactSerializedData[AsymmetricKeyAlgorithm.RSAOAEP256.rawValue]!, encoding: .utf8)!.replacingOccurrences(
            of: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0",
            with: "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0="
            ).data(using: .utf8)!
        
        let jwe = try! JWE(compactSerialization: malformedSerialization)
        
        let decrypter = Decrypter(
            keyDecryptionAlgorithm: .RSAOAEP256,
            decryptionKey: privateKeyAlice2048!,
            contentDecryptionAlgorithm: .A256CBCHS512
            )!
        
        XCTAssertThrowsError(try jwe.decrypt(using: decrypter), "decrypting with wrong enc in header") { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.decryptingFailed(description: "JWE header algorithms do not match encrypter algorithms."))
        }
    }

    func testDecryptWithExplicitDecrypterFailsForWrongKey() {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
            ]
        ]
        
        var error: Unmanaged<CFError>?
        
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print(error!)
            return
        }

        for algorithm in AsymmetricKeyAlgorithm.allCases {
            guard algorithm != .direct else {
                continue
            }
            
            let jwe = try! JWE(compactSerialization: compactSerializedData[algorithm.rawValue]!)
            
            
            let decrypter = Decrypter(
                keyDecryptionAlgorithm: algorithm,
                decryptionKey: key,
                contentDecryptionAlgorithm: .A256CBCHS512
                )!
            
            XCTAssertThrowsError(try jwe.decrypt(using: decrypter))
       }
    }

}
