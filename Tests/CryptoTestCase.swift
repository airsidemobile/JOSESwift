//
//  CryptoTestCase.swift
//  Tests
//
//  Created by Carol Capek on 02.11.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import XCTest

class CryptoTestCase: XCTestCase {
    
    let privateKeyTag = "com.airsidemobile.SwiftJOSE.testPrivateKey"
    var privateKey: SecKey? = nil
    var publicKey: SecKey? = nil
    
    override func setUp() {
        super.setUp()
        setupKeyPair()
    }
    
    override func tearDown() {
        super.tearDown()
    }

    private func setupKeyPair() {
        if let path = Bundle(for: type(of: self)).path(forResource: "TestKey", ofType: "plist"), let keyDict = NSDictionary(contentsOfFile: path), let keyData = Data(base64Encoded: keyDict[privateKeyTag] as! String) {
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: 2048,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: false,
                    kSecAttrApplicationTag as String: privateKeyTag
                ]
            ]

            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
                print(error!)
                return
            }
            
            privateKey = key
            publicKey = SecKeyCopyPublicKey(key)
        }
    }
}
