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
    
    let message = "Hello world!"
    let privateKey = "privateKey"
    let publicKey = "publicKey"
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }

    //TODO: Adapt tests as soon as JWE skeletton is finished and merged
    func testEncryptAndSerialize() {
        let header = JWEHeader(algorithm: .RS512, encryptionAlgorithm: .RS512)
        let payload = JWEPayload(message.data(using: .utf8)!)
        let encrypter = RSAEncrypter(publicKey: publicKey)
        let jwe = JWE(header: header, payload: payload, encrypter: encrypter)
        let compactSerializedJWE = jwe.compactSerialized
        
        XCTAssertEqual(compactSerializedJWE, "eyJhbGciOiJSUzUxMiIsImVuYyI6IlJTNTEyIn0.ZW5jcnlwdGVka2V5.aXY.Y2lwaGVydGV4dA.YXV0aHRhZw")
    }
    
    func testDecrypt() {
        let compactSerializedJWE = "eyJhbGciOiJSUzUxMiIsImVuYyI6IlJTNTEyIn0.ZW5jcnlwdGVka2V5.aXY.Y2lwaGVydGV4dA.YXV0aHRhZw"
        
        let jwe = JWE(compactSerialization: compactSerializedJWE)
        let decrypter = RSADecrypter(privateKey: privateKey)
        let payloadString = String(data: (jwe.decrypt(with: decrypter)?.data())!, encoding: .utf8)!
        
        XCTAssertEqual(payloadString, "Hello world!")
    }
    
}
