//
//  RSAEncrypterTests.swift
//  Tests
//
//  Created by Carol Capek on 22.11.17.
//  Copyright © 2018 Airside Mobile Inc. All rights reserved.
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
        guard publicKey != nil, privateKey != nil else {
            XCTFail()
            return
        }

        let encrypter = RSAEncrypter(algorithm: .RSAPKCS, publicKey: publicKey!)
        guard let cipherText = try? encrypter.encrypt(message.data(using: .utf8)!) else {
            XCTFail()
            return
        }

        var decryptionError: Unmanaged<CFError>?
        guard let plainTextData = SecKeyCreateDecryptedData(privateKey!, .rsaEncryptionPKCS1, cipherText as CFData, &decryptionError) else {
            XCTFail()
            return
        }

        XCTAssertEqual(String(data: plainTextData as Data, encoding: .utf8), message)
    }

    func testPlainTextTooLong() {
        guard publicKey != nil else {
            XCTFail()
            return
        }

        let encrypter = RSAEncrypter(algorithm: .RSAPKCS, publicKey: publicKey!)
        XCTAssertThrowsError(try encrypter.encrypt(Data(count:300))) { (error: Error) in
            XCTAssertEqual(error as? EncryptionError, EncryptionError.plainTextLengthNotSatisfied)
        }
    }

}
