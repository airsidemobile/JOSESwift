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
    let compressedDataBase64URLEncodedString = "C85XCE5NLkotUVT4MH_K0g_ze7YCAA"
    
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

    // Note this test only works as long as the compression factory is invoked before the acutal decryption
    func testDecryptWithNotSupportedZipHeaderValue() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)
        
        let jwe = try! JWE(compactSerialization: jweSerializedNotSupportedZipHeaderValue)
        let decrypter = Decrypter(keyDecryptionAlgorithm: .direct, decryptionKey: symmetricKey, contentDecryptionAlgorithm: .A256CBCHS512)!
        try XCTAssertThrowsError(jwe.decrypt(using: decrypter)) { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.decryptingFailed(description: "The operation couldn’t be completed. (JOSESwift.JOSESwiftError error 22.)"))
        }
    }
    
    // Note this test only works as long as the compression factory is invoked before the acutal encryption
    func testEncryptWithNotSupportedZipHeaderValue() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)
        
        var header = JWEHeader(algorithm: .direct, encryptionAlgorithm: .A256CBCHS512)
        header.zip = "GZIP"
        
        let payload = Payload(data)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: symmetricKey, contentEncyptionAlgorithm: .A256CBCHS512)!
        try XCTAssertThrowsError(JWE(header: header, payload: payload, encrypter: encrypter)) { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.encryptingFailed(description: "The operation couldn’t be completed. (JOSESwift.JOSESwiftError error 22.)"))
        }
    }
    
    func testCompressorFactory() throws {
        let deflateCompressor = try CompressorFactory.makeCompressor(algorithm: CompressionAlgorithm.DEFLATE)
        XCTAssert(deflateCompressor is DeflateCompressor)
        
        let noneCompressor = try CompressorFactory.makeCompressor(algorithm: CompressionAlgorithm.NONE)
        XCTAssert(noneCompressor is NoneCompressor)
        
        try XCTAssertThrowsError(CompressorFactory.makeCompressor(algorithm: nil))
    }
    
    func testNoneCompressor() throws {
        let noneCompressor = try CompressorFactory.makeCompressor(algorithm: CompressionAlgorithm.NONE)
        XCTAssert(noneCompressor is NoneCompressor)
        //test none compress
        XCTAssertEqual(try noneCompressor.compress(data: data), data)
        //test none decompress
        XCTAssertEqual(try noneCompressor.decompress(data: data), data)
    }

    func testDeflateCompressor() throws {
        let deflateCompressor = try CompressorFactory.makeCompressor(algorithm: CompressionAlgorithm.DEFLATE)
        XCTAssert(deflateCompressor is DeflateCompressor)
        
        var compressedData = try deflateCompressor.compress(data: data)
        XCTAssertEqual(compressedData.base64URLEncodedString(), compressedDataBase64URLEncodedString)
        
        compressedData = Data.init(base64URLEncoded: compressedDataBase64URLEncodedString)!
        XCTAssertEqual(try deflateCompressor.decompress(data: compressedData), data)
    }
}
