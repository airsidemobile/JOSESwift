//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//

import Foundation
import IDZSwiftCommonCrypto
import CommonCrypto

public struct AESEncrypter: SymmetricEncrypter {
    func randomCEK(for algorithm: SymmetricEncryptionAlgorithm) -> Data {
        // Todo: Generate CEK using a trusted cryptography library.
        // See: https://mohemian.atlassian.net/browse/JOSE-62.
        return Data(count: 64)
    }
    
    func randomIV(for algorithm: SymmetricEncryptionAlgorithm) -> Data {
        // Todo: Generate IV using a trusted cryptography library.
        // See: https://mohemian.atlassian.net/browse/JOSE-62.
        return "iv".data(using: .utf8)!
    }
    
    func encrypt(_ plaintext: Data, with symmetricKey: Data, using algorithm: SymmetricEncryptionAlgorithm, additionalAuthenticatedData: Data) throws -> SymmetricEncryptionContext {
        // Todo: Throw error if necessary.
        
//        let iv = randomIV(for: algorithm)
        
        let iv = "1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04".hexadecimalToData()!
        
        guard algorithm.checkKeyLength(for: symmetricKey) else {
            throw EncryptionError.keyLengthNotSatisfied
        }
        
        let keys = algorithm.retrieveKeys(from: symmetricKey)
        let hmacKey = keys.hmacKey
        let encryptionKey = keys.encryptionKey
        
        let additionalAuthenticatedDataLengthHex = "00 00 00 00 00 00 01 50".hexadecimalToData()
        
        let cipherText = try aesEncrypt(plaintext, encryptionKey: encryptionKey, using: CCAlgorithm(kCCAlgorithmAES), and: iv)
        
//        var additionalAuthenticatedDataLength = CFSwapInt64(UInt64(additionalAuthenticatedData.count))
//        var aadLengthByte = Data(buffer: UnsafeBufferPointer(start: &additionalAuthenticatedDataLength, count: 1))
//        var aadLengthByte = Data(bytes: &additionalAuthenticatedDataLength, count: MemoryLayout.size(ofValue: additionalAuthenticatedDataLength))
        
        var concatData = additionalAuthenticatedData
        concatData.append(iv)
        concatData.append(cipherText)
        concatData.append(additionalAuthenticatedDataLengthHex!)
        
        let hmacOutput = hmac(input: concatData, hmacKey: hmacKey, using: CCAlgorithm(kCCHmacAlgSHA512))
        
        return SymmetricEncryptionContext(
            ciphertext: cipherText,
            authenticationTag: hmacOutput.subdata(in: 0..<32),
            initializationVector: iv
        )
    }
    
    func aesEncrypt(_ plaintext: Data, encryptionKey: Data, using algorithm: CCAlgorithm, and initializationVector: Data) throws -> Data {
        let dataLength = plaintext.count
        let cryptLength  = size_t(dataLength + kCCBlockSizeAES128)
        var cryptData = Data(count:cryptLength)
        
        let keyLength = size_t(kCCKeySizeAES256)
        let options = CCOptions(kCCOptionPKCS7Padding)
        
        var numBytesEncrypted :size_t = 0
        
        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            plaintext.withUnsafeBytes {dataBytes in
                initializationVector.withUnsafeBytes {ivBytes in
                    encryptionKey.withUnsafeBytes {keyBytes in
                        CCCrypt(CCOperation(kCCEncrypt),
                                algorithm,
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
        } else {
            throw EncryptionError.encryptingFailed(description: "Encryption failed with CryptorStatus: \(cryptStatus).")
        }
        
        return cryptData
    }
    
    func hmac(input: Data, hmacKey: Data, using algorithm: CCAlgorithm) -> Data {
        let keyLength = size_t(kCCKeySizeAES256)
        var hmacOutData = Data(count: 64)
        
        hmacOutData.withUnsafeMutableBytes { hmacOutBytes in
            hmacKey.withUnsafeBytes { hmacKeyBytes in
                input.withUnsafeBytes { inputBytes in
                    CCHmac(algorithm, hmacKeyBytes, keyLength, inputBytes, input.count, hmacOutBytes)
                }
            }
        }
        
        return hmacOutData
    }
    
}

extension String {
    
    func hexadecimalToData() -> Data? {
        var data = Data(capacity: count / 2)
        
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, range: NSMakeRange(0, utf16.count)) { match, flags, stop in
            let byteString = (self as NSString).substring(with: match!.range)
            var num = UInt8(byteString, radix: 16)!
            data.append(&num, count: 1)
        }
        
        guard data.count > 0 else { return nil }
        
        return data
    }
    
}
