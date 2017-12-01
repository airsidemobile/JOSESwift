//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//

import Foundation
import IDZSwiftCommonCrypto
import CommonCrypto

public struct AESDecrypter: SymmetricDecrypter {
    func decrypt(_ context: SymmetricDecryptionContext, with symmetricKey: Data, using algorithm: SymmetricEncryptionAlgorithm) throws -> Data {
        guard algorithm.checkKeyLength(for: symmetricKey) else {
            throw EncryptionError.keyLengthNotSatisfied
        }
        
        let keys = algorithm.retrieveKeys(from: symmetricKey)
        let hmacKey = keys.hmacKey
        let decryptionKey = keys.encryptionKey
        
        let additionalAuthenticatedDataLengthHex = "00 00 00 00 00 00 01 50".hexadecimalToData()
        
        var concatData = context.additionalAuthenticatedData
        concatData.append(context.initializationVector)
        concatData.append(context.ciphertext)
        concatData.append(additionalAuthenticatedDataLengthHex!)
        
        guard authenticateHmac(context.authenticationTag, input: concatData, hmacKey: hmacKey, using: CCAlgorithm(kCCHmacAlgSHA512)) else {
            throw EncryptionError.hmacNotAuthenticated
        }
        
        let plaintext = try aesDecrypt(context.ciphertext, decryptionKey: decryptionKey, using: CCAlgorithm(kCCAlgorithmAES), and: context.initializationVector)
        
        return plaintext
    }
    
    func aesDecrypt(_ ciphertext: Data, decryptionKey: Data, using algorithm: CCAlgorithm, and initializationVector: Data) throws -> Data {
        let dataLength = ciphertext.count
        let decryptLength  = size_t(dataLength + kCCBlockSizeAES128)
        var decryptData = Data(count:decryptLength)
        
        let keyLength = size_t(kCCKeySizeAES256)
        let options = CCOptions(kCCOptionPKCS7Padding)
        
        var numBytesEncrypted :size_t = 0
        
        let decryptStatus = decryptData.withUnsafeMutableBytes {decryptBytes in
            ciphertext.withUnsafeBytes {dataBytes in
                initializationVector.withUnsafeBytes {ivBytes in
                    decryptionKey.withUnsafeBytes {keyBytes in
                        CCCrypt(CCOperation(kCCDecrypt),
                                algorithm,
                                options,
                                keyBytes, keyLength,
                                ivBytes,
                                dataBytes, dataLength,
                                decryptBytes, decryptLength,
                                &numBytesEncrypted)
                    }
                }
            }
        }
        
        if UInt32(decryptStatus) == UInt32(kCCSuccess) {
            decryptData.removeSubrange(numBytesEncrypted..<decryptData.count)
        } else {
            throw EncryptionError.decryptingFailed(description: "Decryption failed with CryptoStatus: \(decryptStatus).")
        }
        
        return decryptData
    }
    
    func authenticateHmac(_ authenticationTag: Data, input: Data, hmacKey: Data, using algorithm: CCAlgorithm) -> Bool { //TODO: Naming
        let keyLength = size_t(kCCKeySizeAES256)
        var hmacOutData = Data(count: 64)
        
        hmacOutData.withUnsafeMutableBytes { hmacOutBytes in
            hmacKey.withUnsafeBytes { hmacKeyBytes in
                input.withUnsafeBytes { inputBytes in
                    CCHmac(algorithm, hmacKeyBytes, keyLength, inputBytes, input.count, hmacOutBytes)
                }
            }
        }
        
        if authenticationTag == hmacOutData.subdata(in: 0..<32) {
            return true
        } else {
            return false
        }
    }
}
