//
//  JWEDirectEncryptionTests.swift
//  Tests
//
//  Created by Daniel Egger on 04.07.18.
//

import XCTest
@testable import JOSESwift

class JWEDirectEncryptionTests: XCTestCase {
    
    func testExample() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)

        let header = JWEHeader(algorithm: .direct, encryptionAlgorithm: .A256CBCHS512)

        let payload = Payload("So Secret! 🔥🌵".data(using: .utf8)!)

        let encrypter = Encrypter(keyEncryptionAlgorithm: .direct, keyEncryptionKey: symmetricKey, contentEncyptionAlgorithm: .A256CBCHS512)!

        let jwe = try! JWE(header: header, payload: payload, encrypter: encrypter)

        let serialization = jwe.compactSerializedString
    }
    
}
