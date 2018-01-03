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

    //TODO: Adapt tests as soon as JWE skeleton is finished and merged
    func testEncryptAndSerialize() {
        let header = JWEHeader(algorithm: .RSAPKCS, encryptionAlgorithm: .AES256CBCHS512)
        let payload = Payload(message.data(using: .utf8)!)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .RSAPKCS, keyEncryptionKey: publicKey!, contentEncyptionAlgorithm: .AES256CBCHS512)
        let jwe = JWE(header: header, payload: payload, encrypter: encrypter)!
        let compactSerializedJWE = jwe.compactSerializedString

        XCTAssertEqual(compactSerializedJWE, "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.ZW5jcnlwdGVkS2V5.aXY.Y2lwaGVydGV4dA.YXV0aFRhZw")
    }

    func testDecrypt() {
        let compactSerializedJWE = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.ZW5jcnlwdGVkS2V5.aXY.Y2lwaGVydGV4dA.YXV0aFRhZw"
        let jwe = try! JWE(compactSerialization: compactSerializedJWE)
        let payloadString = String(data: (jwe.decrypt(with: privateKey!)!).data(), encoding: .utf8)!

        XCTAssertEqual(payloadString, "The true sign of intelligence is not knowledge but imagination.")
    }

}
