//
//  JWEDirectEncryptionTests.swift
//  Tests
//
//  Created by Daniel Egger on 04.07.18.
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

class JWEDirectEncryptionTests: CryptoTestCase {

    let data = "So Secret! 🔥🌵".data(using: .utf8)!

    let serializationFromNimbus = """
            eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiZGlyIn0..HUTNQ9m2Z8Q77tQJhLs5gg.DWQCCkrCPFeZ2-65L9__z83N1exh4oVIk4r\
            OO2_v1eE.8sOW54Soupo_-TdXg5A9qXvokaHzS8cGb__ca3MvuEo
            """

    let keyFromNimbus = Data(bytes: [
        177, 119,  33,  13, 164,  30, 108, 121,
        207, 136, 107, 242,  12, 224,  19, 226,
        198, 134,  17,  71, 173,  75,  42,  61,
         48, 162, 206, 161,  97, 108, 185, 234,
         60, 181,  90,  85,  51, 123,   6, 224,
          4, 122,  29, 230, 151,  12, 244, 127,
        121,  25,   4,  85, 220, 144, 215, 110,
        130,  17,  68, 228, 129, 138,   7, 130
    ])
    
    func testRoundtrip() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)

        let header = JWEHeader(algorithm: .direct, encryptionAlgorithm: .A256CBCHS512)
        let payload = Payload(data)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: symmetricKey, contentEncyptionAlgorithm: .A256CBCHS512)!

        let jwe = try! JWE(header: header, payload: payload, encrypter: encrypter)
        let serialization = jwe.compactSerializedString

        try! XCTAssertEqual(JWE(compactSerialization: serialization).decrypt(with: symmetricKey).data(), data)
    }

    func testDecryptFromNimbus() {
        let symmetricKey = keyFromNimbus

        let jwe = try! JWE(compactSerialization: serializationFromNimbus)

        try! XCTAssertEqual(jwe.decrypt(with: symmetricKey).data(), data)
    }

    func testDecryptWithWrongSymmetricKey() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)

        let jwe = try! JWE(compactSerialization: serializationFromNimbus)

        XCTAssertThrowsError(try jwe.decrypt(with: symmetricKey))
    }

    func testDecryptWithCorrectAlgWrongKeyType() {
        let privateKey = privateKey2048!

        let jwe = try! JWE(compactSerialization: serializationFromNimbus)

        XCTAssertThrowsError(try jwe.decrypt(with: privateKey))
    }

    func testDecryptWithWrongAlgCorrectKeyType() {
        // replacing `{"enc":"A256CBC-HS512","alg":"dir"}` with `{"enc":"A256CBC-HS512","alg":"RSA1_5"}`
        let serialization = serializationFromNimbus.replacingOccurrences(
            of: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiZGlyIn0",
            with: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBMV81In0"
        )

        let symmetricKey = keyFromNimbus

        let jwe = try! JWE(compactSerialization: serialization)

        XCTAssertThrowsError(try jwe.decrypt(with: symmetricKey))
    }

    func testDecryptWithWrongAlgWrongKeyType() {
        // replacing `{"enc":"A256CBC-HS512","alg":"dir"}` with `{"enc":"A256CBC-HS512","alg":"RSA1_5"}`
        let serialization = serializationFromNimbus.replacingOccurrences(
            of: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiZGlyIn0",
            with: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBMV81In0"
        )

        let privateKey = privateKey2048!

        let jwe = try! JWE(compactSerialization: serialization)

        XCTAssertThrowsError(try jwe.decrypt(with: privateKey))
    }
    
}
