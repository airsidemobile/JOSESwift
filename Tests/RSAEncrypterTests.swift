//
//  RSAEncrypterTests.swift
//  Tests
//
//  Created by Carol Capek on 22.11.17.
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

class RSAEncrypterTests: CryptoTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testEncrypting() {
        guard publicKey2048 != nil, privateKey2048 != nil else {
            XCTFail()
            return
        }

        let encrypter = RSAEncrypter(algorithm: .RSAPKCS, publicKey: publicKey2048!)
        guard let cipherText = try? encrypter.encrypt(message.data(using: .utf8)!) else {
            XCTFail()
            return
        }

        var decryptionError: Unmanaged<CFError>?
        guard let plainTextData = SecKeyCreateDecryptedData(privateKey2048!, .rsaEncryptionPKCS1, cipherText as CFData, &decryptionError) else {
            XCTFail()
            return
        }

        XCTAssertEqual(String(data: plainTextData as Data, encoding: .utf8), message)
    }

    func testPlainTextTooLong() {
        guard publicKey2048 != nil else {
            XCTFail()
            return
        }

        let encrypter = RSAEncrypter(algorithm: .RSAPKCS, publicKey: publicKey2048!)
        XCTAssertThrowsError(try encrypter.encrypt(Data(count:300))) { (error: Error) in
            XCTAssertEqual(error as? EncryptionError, EncryptionError.plainTextLengthNotSatisfied)
        }
    }

}
