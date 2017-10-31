//
//  JWETests.swift
//  Tests
//
//  Created by Carol Capek on 31.10.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import XCTest
@testable import SwiftJOSE

class JWETests: XCTestCase {
    
    let message = "so cool"
    let symKey = "symmetricKey"
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }

    //TODO: Adapt tests as soon as JWE skeletton is finished and merged
    func testEncryptAndSerialize() {
        let header = JWEHeader(algorithm: .rs512, encryptionAlgorithm: .rs512)
        let payload = JWEPayload(message.data(using: .utf8)!)
        let encrypter = AESEncrypter(publicKey: symKey)
        let jwe = JWE(header: header, payload: payload, encrypter: encrypter)
        let compactSerializedJWE = jwe.compactSerialized
        
        XCTAssertEqual(compactSerializedJWE, "eyJhbGciOiJSUzUxMiIsImVuYyI6IlJTNTEyIn0.ZW5jcnlwdGVka2V5.aXY.Y2lwaGVydGV4dA.YXV0aHRhZw")
        
        let secondJWE = JWE(compactSerialization: compactSerializedJWE)
        let decrypter = AESDecrypter(privateKey: symKey)
        let payloadString = String(data: (secondJWE.decrypt(with: decrypter)?.data())!, encoding: .utf8)!
        
        XCTAssertEqual(payloadString, "so cool")
        
    }
    
}
