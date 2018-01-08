//
//  AES.swift
//  SwiftJOSE
//
//  Created by Carol Capek on 04.01.18.
//

import Foundation
import CommonCrypto

public struct AES {

    public static func encrypt(plaintext: Data, encryptionKey: Data, algorithm: SymmetricEncryptionAlgorithm, iv: Data) -> Data {
        switch algorithm {
        case .AES256CBCHS512:
            encrypt256(plaintext: plaintext, encryptionKey: encryptionKey, iv: iv)
        }
    }

    public static func encrypt256(plaintext: Data, encryptionKey: Data, iv: Data) -> Data {
        let dataLength = plaintext.count

        let cryptLength  = size_t(dataLength + kCCBlockSizeAES128)
        var cryptData = Data(count:cryptLength)

        let keyLength = size_t(kCCKeySizeAES256)
        let options = CCOptions(kCCOptionPKCS7Padding)

        var numBytesEncrypted: size_t = 0

        // In funktion auslagern
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
            cryptData.removeSubrange(numBytesEncrypted..<cryptLength)
        } else {
            throw EncryptionError.encryptingFailed(description: "Encryption failed with CryptorStatus: \(cryptStatus).")
        }

        return cryptData
    }
}
