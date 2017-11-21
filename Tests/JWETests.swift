//
//  JWETests.swift
//  Tests
//
//  Created by Carol Capek on 31.10.17.
//

import XCTest
@testable import SwiftJOSE

class JWETests: CryptoTestCase {
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }

    //TODO: Adapt tests as soon as JWE skeleton is finished and merged
    func testEncryptAndSerialize() {
        let header = JWEHeader(algorithm: .RSAOAEP, encryptionAlgorithm: .AESGCM256)
        let payload = Payload(message.data(using: .utf8)!)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .RSAOAEP, keyEncryptionKey: publicKey!, contentEncyptionAlgorithm: .AESGCM256, contentEncryptionKey: privateKey!)
        let jwe = JWE(header: header, payload: payload, encrypter: encrypter)
        let compactSerializedJWE = jwe.compactSerialized
        
        XCTAssertEqual(compactSerializedJWE, "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.ZW5jcnlwdGVkS2V5.aXY.Y2lwaGVydGV4dA.YXV0aFRhZw")
    }
    
    func testDecrypt() {
        let compactSerializedJWE = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.ZW5jcnlwdGVkS2V5.aXY.Y2lwaGVydGV4dA.YXV0aFRhZw"
        
        let jwe = try! JWE(compactSerialization: compactSerializedJWE)
        let decrypter = Decrypter(keyDecryptionAlgorithm: .RSAOAEP, keyDecryptionKey: privateKey!)
        let payloadString = String(data: (jwe.decrypt(with: decrypter)?.data())!, encoding: .utf8)!
        
        XCTAssertEqual(payloadString, "The true sign of intelligence is not knowledge but imagination.")
    }
    
}
