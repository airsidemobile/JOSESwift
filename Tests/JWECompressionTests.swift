//
//  JWECompressionTests.swift
//  Tests
//
//  Created by Florian Häser on 24.12.18.
//

import XCTest
@testable import JOSESwift

class JWECompressionTests: RSACryptoTestCase {
    
    let data = "So Secret! 🔥🌵".data(using: .utf8)!
    
    let jweSerializedNotSupportedZipHeaderValue = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiemlwIjoiR1pJUCJ9..I62WKaitlHoJ-Kz3zvQ-Tw.Tu9hk_AMRMRTc8ggsoWifFS979Nz8xt-xx4FpF6waeE.w7c8eAGXpUD3tNskLzdl17s4vsCCSUwe5bRFpJg1kUs"
    
    @available(*, deprecated)
    func testRoundtripWithLegacyDecrypter() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)
        
        var header = JWEHeader(algorithm: .direct, encryptionAlgorithm: .A256CBCHS512)
        header.zip = "DEF"
        
        let payload = Payload(data)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: symmetricKey, contentEncyptionAlgorithm: .A256CBCHS512)!
        
        let jwe = try! JWE(header: header, payload: payload, encrypter: encrypter)
        let serialization = jwe.compactSerializedString
        
        try! XCTAssertEqual(JWE(compactSerialization: serialization).decrypt(with: symmetricKey).data(), data)
    }
    
    func testRoundtrip() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)
        
        var header = JWEHeader(algorithm: .direct, encryptionAlgorithm: .A256CBCHS512)
        header.zip = "DEF"
        
        let payload = Payload(data)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: symmetricKey, contentEncyptionAlgorithm: .A256CBCHS512)!
        
        let jwe = try! JWE(header: header, payload: payload, encrypter: encrypter)
        let serialization = jwe.compactSerializedString
        
        let decrypter = Decrypter(keyDecryptionAlgorithm: .direct, decryptionKey: symmetricKey, contentDecryptionAlgorithm: .A256CBCHS512)!
        
        try! XCTAssertEqual(JWE(compactSerialization: serialization).decrypt(using: decrypter).data(), data)
    }
    
    func testEncryptWithNotSupportedZipHeaderValue() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)
        
        var header = JWEHeader(algorithm: .direct, encryptionAlgorithm: .A256CBCHS512)
        header.zip = "GZIP"
        
        let payload = Payload(data)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: symmetricKey, contentEncyptionAlgorithm: .A256CBCHS512)!
        
        try XCTAssertThrowsError(JWE(header: header, payload: payload, encrypter: encrypter))
    }
    
    // Note this test only works as long as the guard statement is before the actual decryption operation
    func testDecryptWithNotSupportedZipHeaderValue() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)
        
        let jwe = try! JWE(compactSerialization: jweSerializedNotSupportedZipHeaderValue)
        let decrypter = Decrypter(keyDecryptionAlgorithm: .direct, decryptionKey: symmetricKey, contentDecryptionAlgorithm: .A256CBCHS512)!
        try XCTAssertThrowsError(jwe.decrypt(using: decrypter))
    }
}
