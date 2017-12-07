//
//  AESEncrypterTests.swift
//  Tests
//
//  Created by Carol Capek on 28.11.17.
//

import XCTest
@testable import SwiftJOSE
import IDZSwiftCommonCrypto
import CommonCrypto

class AESEncrypterTests: CryptoTestCase {

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    /**
     [RFC-7518]: https://tools.ietf.org/html/rfc7518#appendix-B.3 "AES_256_CBC_HMAC_SHA_512 Test data"
     
     Tests the `AES` encryption implementation for AES_256_CBC_HMAC_SHA_512 with the test data provided in the [RFC-7518]
     */
    func testEncrypting() {
        let plaintext = "41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20 6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75 69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65 74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62 65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69 6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66 20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f 75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65".hexadecimalToData()!
        let additionalAuthenticatedData = "54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63 69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20 4b 65 72 63 6b 68 6f 66 66 73".hexadecimalToData()!

        let encrypter = AESEncrypter()
        let cek = try! encrypter.randomCEK(for: .AES256CBCHS512)
        let symmetricEncryptionContext = try! encrypter.encrypt(plaintext, with: cek, using: .AES256CBCHS512, additionalAuthenticatedData: additionalAuthenticatedData)

        // Check if the symmetric encryption was successful but using the CommonCrypto framework and not the implemented decrypt method
        let keys = try! SymmetricEncryptionAlgorithm.AES256CBCHS512.retrieveKeys(from: cek)
        let hmacKey = keys.hmacKey
        let encryptionKey = keys.encryptionKey

        var concatData = additionalAuthenticatedData
        concatData.append(symmetricEncryptionContext.initializationVector)
        concatData.append(symmetricEncryptionContext.ciphertext)
        concatData.append(additionalAuthenticatedData.getByteLengthAsOctetHexData())

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
