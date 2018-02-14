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
@testable import SwiftJOSE

class RSADecrypterTests: CryptoTestCase {
    let cipherTextBase64URL = "YkzUN55RBG1igsrL-7ofPPWruTjxNMS3Bl1_a3i-dVKBjiN6kH88j8G3iB3eLWFxbiKZvx0LmkP7J65-frpOgF41SlltjJ62LEZOICm4q21Q4MNqL_Vf7kIjh8DziEJkElEz5W4flhI6YQ-9wW_PQ-coBIPIZiFlw6peKAolz8xcevbUmnqIH6A3hOFLK23J2cWDSWgxHEBIYtZ6whQCJYL4vq5lAFNaEoDaE_cgL6LItY4t-vR1exTJSOlCGAv4uM1Kelk6uitaFk2c0h79u3UpFN_wa02m_PPdgTguRdxwRsCpsQhOKmEakl8LR6NTbIrdB13UoL2tdybltVeUCw"

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testDecrypting() {
        guard privateKey2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSAPKCS, privateKey: privateKey2048!)
        let plainText = try! decrypter.decrypt(Data(base64URLEncoded: cipherTextBase64URL)!)

        XCTAssertEqual(plainText, message.data(using: .utf8))
    }

    func testCipherTextLengthTooLong() {
        guard privateKey2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSAPKCS, privateKey: privateKey2048!)
        XCTAssertThrowsError(try decrypter.decrypt(Data(count: 300))) { (error: Error) in
            XCTAssertEqual(error as? EncryptionError, EncryptionError.cipherTextLenghtNotSatisfied)
        }
    }

}
