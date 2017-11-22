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
    let cipherTextBase64URL = "RmKR9kGcxuf6OHkbykkPMeMiYyakVg9EtpVmZtVlQSq8EKCKmIvBd7Vw8dPu-0XpcVpKPyzSjQFRhvPBJd_dDVQKShjSzw-SB7_zfA8COo4MqAwkUEOrTEmZCsE1VdQ3dKK3sc5OoYlzOLrf8I4v4gUzXHajiBxTWcvQY3plkdfOb6Tqe9ff7FDbpO-7iCJxn3UkDVVwS3AHu15PboVQ88WOIMhVAwj5NaeWKtWw3kPfdFaaqoisbSBncdl1l7ZOYrUHGLow9QjVnS2U8CmlkNnOsHOLB6C89Jz5HsmsAzneiYlYbjKR7FL8I2ooW1CNwB_eAVTwrJIYJrvBrF8LVA"
    
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testEncrypting() {
        guard publicKey != nil else {
            XCTFail()
            return
        }
        
        let encrypter = RSAEncrypter(publicKey: publicKey!)
        let cipherText = encrypter.encrypt(message.data(using: .utf8)!)
        
        XCTAssertEqual(cipherText, cipherTextBase64URL.data(using: .utf8))
    }
}
