//
//  AESEncrypterTests.swift
//  Tests
//
//  Created by Carol Capek on 28.11.17.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
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
import CommonCrypto

class AESEncrypterTests: RSACryptoTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    /// Tests the `AES` encryption implementation for AES_128_CBC_HMAC_SHA_256 with the test data provided in the [RFC-7518](https://tools.ietf.org/html/rfc7518#appendix-B.1).
    func testEncryptingA128CBCHS256() {
        let plaintext = "41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20 6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75 69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65 74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62 65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69 6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66 20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f 75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65".hexadecimalToData()!
        let additionalAuthenticatedData = "54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63 69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20 4b 65 72 63 6b 68 6f 66 66 73".hexadecimalToData()!
        let algorithm = SymmetricKeyAlgorithm.A128CBCHS256
        let cek = try! SecureRandom.generate(count: algorithm.keyLength)
        let encrypter = AESEncrypter(algorithm: algorithm)
        let symmetricEncryptionContext = try! encrypter.encrypt(plaintext, with: cek, additionalAuthenticatedData: additionalAuthenticatedData.base64URLEncodedData())

        // Check if the symmetric encryption was successful by using the CommonCrypto framework and not the implemented decrypt method.
        let keys = try! algorithm.retrieveKeys(from: cek)
        let hmacKey = keys.hmacKey
        let encryptionKey = keys.encryptionKey

        var concatData = String(data: additionalAuthenticatedData, encoding: .utf8)!.data(using: .utf8)!.base64URLEncodedData()
        concatData.append(symmetricEncryptionContext.initializationVector)
        concatData.append(symmetricEncryptionContext.ciphertext)
        concatData.append(String(data: additionalAuthenticatedData, encoding: .utf8)!.data(using: .utf8)!.base64URLEncodedData().getByteLengthAsOctetHexData())

        let keyLength = size_t(kCCKeySizeAES128)
        var macOutData = Data(count: 64)

        macOutData.withUnsafeMutableBytes { macOutBytes in
            hmacKey.withUnsafeBytes { hmacKeyBytes in
                concatData.withUnsafeBytes { concatBytes in
                    CCHmac(CCAlgorithm(kCCHmacAlgSHA256), hmacKeyBytes, keyLength, concatBytes, concatData.count, macOutBytes)
                }
            }
        }

        XCTAssertEqual(macOutData.subdata(in: 0..<16), symmetricEncryptionContext.authenticationTag)

        let dataLength = symmetricEncryptionContext.ciphertext.count
        let cryptLength  = size_t(dataLength + kCCBlockSizeAES128)
        var cryptData = Data(count:cryptLength)

        let options = CCOptions(kCCOptionPKCS7Padding)

        var numBytesEncrypted: size_t = 0

        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            symmetricEncryptionContext.ciphertext.withUnsafeBytes {dataBytes in
                symmetricEncryptionContext.initializationVector.withUnsafeBytes {ivBytes in
                    encryptionKey.withUnsafeBytes {keyBytes in
                        CCCrypt(CCOperation(kCCDecrypt),
                                CCAlgorithm(kCCAlgorithmAES128),
                                options,
                                keyBytes, keyLength,
                                ivBytes,
                                dataBytes, dataLength,
                                cryptBytes, cryptLength,
                                &numBytesEncrypted)
                    }
                }
            }
        }

        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.removeSubrange(numBytesEncrypted..<cryptData.count)
        }

        XCTAssertEqual(cryptData, plaintext)
    }


    /// Tests the `AES` encryption implementation for AES_256_CBC_HMAC_SHA_512 with the test data provided in the [RFC-7518](https://tools.ietf.org/html/rfc7518#appendix-B.3).
    func testEncryptingA256CBCHS512() {
        let plaintext = "41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20 6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75 69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65 74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62 65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69 6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66 20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f 75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65".hexadecimalToData()!
        let additionalAuthenticatedData = "54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63 69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20 4b 65 72 63 6b 68 6f 66 66 73".hexadecimalToData()!

        let cek = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)
        let encrypter = AESEncrypter(algorithm: .A256CBCHS512)
        let symmetricEncryptionContext = try! encrypter.encrypt(plaintext, with: cek, additionalAuthenticatedData: additionalAuthenticatedData.base64URLEncodedData())

        // Check if the symmetric encryption was successful by using the CommonCrypto framework and not the implemented decrypt method.
        let keys = try! SymmetricKeyAlgorithm.A256CBCHS512.retrieveKeys(from: cek)
        let hmacKey = keys.hmacKey
        let encryptionKey = keys.encryptionKey

        var concatData = String(data: additionalAuthenticatedData, encoding: .utf8)!.data(using: .utf8)!.base64URLEncodedData()
        concatData.append(symmetricEncryptionContext.initializationVector)
        concatData.append(symmetricEncryptionContext.ciphertext)
        concatData.append(String(data: additionalAuthenticatedData, encoding: .utf8)!.data(using: .utf8)!.base64URLEncodedData().getByteLengthAsOctetHexData())

        let keyLength = size_t(kCCKeySizeAES256)
        var macOutData = Data(count: 64)

        macOutData.withUnsafeMutableBytes { macOutBytes in
            hmacKey.withUnsafeBytes { hmacKeyBytes in
                concatData.withUnsafeBytes { concatBytes in
                    CCHmac(CCAlgorithm(kCCHmacAlgSHA512), hmacKeyBytes, keyLength, concatBytes, concatData.count, macOutBytes)
                }
            }
        }

        XCTAssertEqual(macOutData.subdata(in: 0..<32), symmetricEncryptionContext.authenticationTag)

        let dataLength = symmetricEncryptionContext.ciphertext.count
        let cryptLength  = size_t(dataLength + kCCBlockSizeAES128)
        var cryptData = Data(count:cryptLength)

        let options = CCOptions(kCCOptionPKCS7Padding)

        var numBytesEncrypted: size_t = 0

        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            symmetricEncryptionContext.ciphertext.withUnsafeBytes {dataBytes in
                symmetricEncryptionContext.initializationVector.withUnsafeBytes {ivBytes in
                    encryptionKey.withUnsafeBytes {keyBytes in
                        CCCrypt(CCOperation(kCCDecrypt),
                                CCAlgorithm(kCCAlgorithmAES128),
                                options,
                                keyBytes, keyLength,
                                ivBytes,
                                dataBytes, dataLength,
                                cryptBytes, cryptLength,
                                &numBytesEncrypted)
                    }
                }
            }
        }

        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.removeSubrange(numBytesEncrypted..<cryptData.count)
        }

        XCTAssertEqual(cryptData, plaintext)
    }
}
