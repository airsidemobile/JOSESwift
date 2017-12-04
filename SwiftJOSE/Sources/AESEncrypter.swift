//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//

import Foundation
import IDZSwiftCommonCrypto
import CommonCrypto

/// A `SymmetricEncrypter` to encrypt plaintext with an `AES` algorithm.
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

        // Generate random intitializationVector.
//        let iv = randomIV(for: algorithm)
        
        let iv = "1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04".hexadecimalToData()!
        
        // Check if the key length contains both HMAC key and the actual symmetric key.
        guard algorithm.checkKeyLength(for: symmetricKey) else {
            throw EncryptionError.keyLengthNotSatisfied
        }
        
        // Get the two keys for the HMAC and the symmetric encryption.
        let keys = algorithm.retrieveKeys(from: symmetricKey)
        let hmacKey = keys.hmacKey
        let encryptionKey = keys.encryptionKey
        
        let additionalAuthenticatedDataLengthHex = "00 00 00 00 00 00 01 50".hexadecimalToData()
        
        // Encrypt the plaintext with a symmetric encryption key, a symmetric encryption algorithm and an initialization vector,
        // return the ciphertext if no error occured.
        let cipherText = try aesEncrypt(plaintext, encryptionKey: encryptionKey, using: CCAlgorithm(kCCAlgorithmAES), and: iv)
        let additionalAuthenticatedDataLength = getAdditionalAuthenticatedDataLength(from: additionalAuthenticatedData)
        
        // Put the input data for the HMAC together. It consists of A || IV || E || AL.
        var concatData = additionalAuthenticatedData
        concatData.append(iv)
        concatData.append(cipherText)
        concatData.append(additionalAuthenticatedDataLength)
        
        // Calculate the HMAC with the concatenated input data, the HMAC key and the HMAC algorithm.
        let hmacOutput = hmac(input: concatData, hmacKey: hmacKey, using: CCAlgorithm(kCCHmacAlgSHA512))
        let authenticationTag = hmacOutput.subdata(in: 0..<32)
        
        return SymmetricEncryptionContext(
            ciphertext: cipherText,
            authenticationTag: authenticationTag,
            initializationVector: iv
        )
    }
    
    /**
     Encrypts a plain text using a given `AES` algorithm, the corresponding symmetric key and an initialization vector.
     - Parameters:
        - plaintext: The plain text to encrypt.
        - encryptionKey: The symmetric key.
        - algorithm: The algorithm used to encrypt the plain text.
        - initializationVector: The initial block.
     
     - Throws:
        - `EncryptionError.encryptingFailed(description: String)`: If the encryption failed with a specific error.
     
     - Returns: The cipher text (encrypted plain text).
     */
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
    
    /**
     Calculates a HMAC of an input with a specific HMAC algorithm and the corresponding HMAC key.
     - Parameters:
        - input: The input to calculate a HMAC of.
        - hmacKey: The key for the HMAC algorithm.
        - algorithm: The algorithm used to calculate the HMAC.
     
     - Returns: The calculated HMAC.
     */
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
    
    func getAdditionalAuthenticatedDataLength(from additionalAuthenticatedData: Data) -> Data {
        let dataLength = UInt64(additionalAuthenticatedData.count * 8)
        var dataLengthInHex = String(dataLength, radix: 16, uppercase: false)
        
        var additionalAuthenticatedDataLenghtBytes = [UInt8](repeatElement(0x00, count: 8))
        
        var dataIndex = additionalAuthenticatedDataLenghtBytes.count-1
        for i in stride(from: 0, to: dataLengthInHex.count, by: 2) {
            var hexChunk = ""
            if dataLengthInHex.count == 1 {
                hexChunk = "0\(dataLengthInHex)"
            } else {
                let endIndex = dataLengthInHex.index(dataLengthInHex.endIndex, offsetBy: -i)
                let startIndex = dataLengthInHex.index(endIndex, offsetBy: -2)
                let range = Range(uncheckedBounds: (lower: startIndex, upper: endIndex))
                hexChunk = String(dataLengthInHex[range])
                dataLengthInHex.removeLast(2)
            }

// TODO: Delete as soon as the IV and the additionalAuthenticatedData length is calculated in a right way.
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
