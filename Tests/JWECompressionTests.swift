// swiftlint:disable force_unwrapping
// swiftlint:disable force_cast
//
//  JWECompressionTests.swift
//  Tests
//
//  Created by Florian Häser on 24.12.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2024 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import XCTest
@testable import JOSESwift

class JWECompressionTests: RSACryptoTestCase {

    let data = "So Secret! 🔥🌵".data(using: .utf8)!
    let compressedDataBase64URLEncodedString = "C85XCE5NLkotUVT4MH_K0g_ze7YCAA"

    let jweSerializedNotSupportedZipHeaderValue = """
        eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiemlwIjoiR1pJUCJ9..I62W\
        KaitlHoJ-Kz3zvQ-Tw.Tu9hk_AMRMRTc8ggsoWifFS979Nz8xt-xx4FpF6waeE.w7c8eAG\
        XpUD3tNskLzdl17s4vsCCSUwe5bRFpJg1kUs
        """

    func testRoundtripDirectEncryption() {
        let symmetricKey = try! SecureRandom.generate(count: ContentEncryptionAlgorithm.A256CBCHS512.keyLength)

        var header = JWEHeader(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256CBCHS512)
        header.zip = "DEF"

        let payload = Payload(data)
        let encrypter = Encrypter(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: symmetricKey)!

        let jwe = try! JWE(header: header, payload: payload, encrypter: encrypter)
        let serialization = jwe.compactSerializedString

        let decrypter = Decrypter(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256CBCHS512, decryptionKey: symmetricKey)!

        try! XCTAssertEqual(JWE(compactSerialization: serialization).decrypt(using: decrypter).data(), data)
    }

    func testRoundtripKeyEncryption() {
        var header = JWEHeader(keyManagementAlgorithm: .RSA1_5, contentEncryptionAlgorithm: .A256CBCHS512)
        header.zip = "DEF"

        let payload = Payload(data)
        let encrypter = Encrypter(keyManagementAlgorithm: .RSA1_5, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: publicKeyAlice2048!)!

        let jwe = try! JWE(header: header, payload: payload, encrypter: encrypter)
        let serialization = jwe.compactSerializedString

        let decrypter = Decrypter(keyManagementAlgorithm: .RSA1_5, contentEncryptionAlgorithm: .A256CBCHS512, decryptionKey: privateKeyAlice2048!)!

        try! XCTAssertEqual(JWE(compactSerialization: serialization).decrypt(using: decrypter).data(), data)
    }

    // Note this test only works as long as the compression factory is invoked before the acutal decryption
    func testDecryptWithNotSupportedZipHeaderValue() {
        let symmetricKey = try! SecureRandom.generate(count: ContentEncryptionAlgorithm.A256CBCHS512.keyLength)

        let jwe = try! JWE(compactSerialization: jweSerializedNotSupportedZipHeaderValue)
        let decrypter = Decrypter(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256CBCHS512, decryptionKey: symmetricKey)!
        try XCTAssertThrowsError(jwe.decrypt(using: decrypter)) { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.compressionAlgorithmNotSupported)
        }
    }

    // Note this test only works as long as the compression factory is invoked before the acutal encryption
    func testEncryptWithNotSupportedZipHeaderValue() {
        let symmetricKey = try! SecureRandom.generate(count: ContentEncryptionAlgorithm.A256CBCHS512.keyLength)

        var header = JWEHeader(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256CBCHS512)
        header.zip = "GZIP"

        let payload = Payload(data)
        let encrypter = Encrypter(keyManagementAlgorithm: .direct, contentEncryptionAlgorithm: .A256CBCHS512, encryptionKey: symmetricKey)!
        try XCTAssertThrowsError(JWE(header: header, payload: payload, encrypter: encrypter)) { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.compressionAlgorithmNotSupported)
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
        // test none compress
        XCTAssertEqual(try noneCompressor.compress(data: data), data)
        // test none decompress
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
// swiftlint:enable force_unwrapping
// swiftlint:enable force_cast
