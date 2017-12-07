//
//  RSADecrypterTests.swift
//  Tests
//
//  Created by Carol Capek on 23.11.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
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
        guard privateKey != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSAPKCS, privateKey: privateKey!)
        let plainText = try! decrypter.decrypt(Data(base64URLEncoded: cipherTextBase64URL)!)

        XCTAssertEqual(plainText, message.data(using: .utf8))
    }

    func testCipherTextLengthTooLong() {
        guard privateKey != nil else {
            XCTFail()
            return
        }

        let decrypter = RSADecrypter(algorithm: .RSAPKCS, privateKey: privateKey!)
        XCTAssertThrowsError(try decrypter.decrypt(Data(count: 300))) { (error: Error) in
            XCTAssertEqual(error as? EncryptionError, EncryptionError.cipherTextLenghtNotSatisfied)
        }
    }

}
