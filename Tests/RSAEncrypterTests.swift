//
//  RSAEncrypterTests.swift
//  Tests
//
//  Created by Carol Capek on 22.11.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
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
        
        let encrypter = RSAEncrypter(publicKey: publicKey!)
        guard let cipherText = encrypter.encrypt(message.data(using: .utf8)!, using: .RSAPKCS) else {
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
        
    }
}
