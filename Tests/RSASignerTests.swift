//
//  RSASignerTests.swift
//  Tests
//
//  Created by Carol Capek on 02.11.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import XCTest
@testable import SwiftJOSE

class RSASignerTests: CryptoTestCase {
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testSigning() {
        print(publicKey)
        print(privateKey)
        let signer = RSASigner(key: "str")
    }
    
}
