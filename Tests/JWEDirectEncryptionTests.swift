// swiftlint:disable force_unwrapping
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

class JWEDirectEncryptionTests: RSACryptoTestCase {

    let data = "So Secret! 🔥🌵".data(using: .utf8)!

    let serializationFromNimbus = """
        eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiZGlyIn0..HUTNQ9m2Z8Q77tQJhLs5gg.DWQCCkrCPFeZ2-65L9__z83N1exh4oVIk4rOO2_\
        v1eE.8sOW54Soupo_-TdXg5A9qXvokaHzS8cGb__ca3MvuEo
        """

    let keyFromNimbus = Data([
        177, 119, 33, 13, 164, 30, 108, 121,
        207, 136, 107, 242, 12, 224, 19, 226,
        198, 134, 17, 71, 173, 75, 42, 61,
         48, 162, 206, 161, 97, 108, 185, 234,
         60, 181, 90, 85, 51, 123, 6, 224,
          4, 122, 29, 230, 151, 12, 244, 127,
        121, 25, 4, 85, 220, 144, 215, 110,
        130, 17, 68, 228, 129, 138, 7, 130
    ])

    @available(*, deprecated)

    func testRoundtripA128CBCHS256() {
        let algorithm = SymmetricKeyAlgorithm.A128CBCHS256
        let symmetricKey = try! SecureRandom.generate(count: algorithm.keyLength)

        let header = JWEHeader(algorithm: .direct, encryptionAlgorithm: algorithm)
        let payload = Payload(data)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: symmetricKey, contentEncyptionAlgorithm: algorithm)!

        let jwe = try! JWE(header: header, payload: payload, encrypter: encrypter)
        let serialization = jwe.compactSerializedString

        try! XCTAssertEqual(JWE(compactSerialization: serialization).decrypt(with: symmetricKey).data(), data)
    }

    @available(*, deprecated)
    func testRoundtripA256CBCHS512() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)

        let header = JWEHeader(algorithm: .direct, encryptionAlgorithm: .A256CBCHS512)
        let payload = Payload(data)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: symmetricKey, contentEncyptionAlgorithm: .A256CBCHS512)!

        let jwe = try! JWE(header: header, payload: payload, encrypter: encrypter)
        let serialization = jwe.compactSerializedString

        try! XCTAssertEqual(JWE(compactSerialization: serialization).decrypt(with: symmetricKey).data(), data)
    }

    @available(*, deprecated)
    func testDecryptFromNimbus() {
        let symmetricKey = keyFromNimbus

        let jwe = try! JWE(compactSerialization: serializationFromNimbus)

        try! XCTAssertEqual(jwe.decrypt(with: symmetricKey).data(), data)
    }

    @available(*, deprecated)
    func testDecryptWithWrongSymmetricKey() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)

        let jwe = try! JWE(compactSerialization: serializationFromNimbus)

        XCTAssertThrowsError(try jwe.decrypt(with: symmetricKey))
    }

    @available(*, deprecated)
    func testDecryptWithCorrectAlgWrongKeyType() {
        let privateKey = privateKeyAlice2048!

        let jwe = try! JWE(compactSerialization: serializationFromNimbus)

        XCTAssertThrowsError(try jwe.decrypt(with: privateKey))
    }

    @available(*, deprecated)
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

    @available(*, deprecated)
    func testDecryptWithWrongAlgWrongKeyType() {
        // replacing `{"enc":"A256CBC-HS512","alg":"dir"}` with `{"enc":"A256CBC-HS512","alg":"RSA1_5"}`
        let serialization = serializationFromNimbus.replacingOccurrences(
            of: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiZGlyIn0",
            with: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBMV81In0"
        )

        let privateKey = privateKeyAlice2048!

        let jwe = try! JWE(compactSerialization: serialization)

        XCTAssertThrowsError(try jwe.decrypt(with: privateKey))
    }

    @available(*, deprecated)
    func testDecryptWithEncryptedKeyPresent() {
        let encryptedKey = """
            c3HOjtBLx3xt3RYMx2WexgbYpcszeqiWXZmeBaLIUb8BXsETRxHDFUyyAt6Q8dIYX22kQs9Kte7AL1CcVxS0C2sx_yu7xDZ4s67cHW1AMbf\
            qqqhyaUSS5BkyTIhLgEbo34ohxP0bYq-enlu8hlOYWhwh-yLSj1mRCSYufv8ik6QhoJ14P981M_O8Fl0XMGe7Ki3jdui_MKj8NKN-96McS4\
            0zhtxZRuq1ZYzmmu1fAh3MA5LZkUBInnW5GpNfar3Lap1UnIt1yTJf9U9zk48qU9ymPnbD8oYm8ec15lsmCuuMcB1uG3SgFYAGTZStgX1My\
            KjyAlDGiZrKo6p0Hn8piw
            """

        var serialization = serializationFromNimbus
        var parts = serialization.split(separator: ".").map {
            String($0)
        }
        parts.insert(encryptedKey, at: 1)
        serialization = parts.joined(separator: ".")

        let symmetricKey = keyFromNimbus

        let jwe = try! JWE(compactSerialization: serialization)

        XCTAssertThrowsError(try jwe.decrypt(with: symmetricKey))
    }

}
