//
//  AES.swift
//  SwiftJOSE
//
//  Created by Carol Capek on 04.01.18.
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

import Foundation
import IDZSwiftCommonCrypto
import CommonCrypto

fileprivate extension SymmetricKeyAlgorithm {
    var ccAlgorithm: CCAlgorithm {
        switch self {
        case .AES256CBCHS512:
            return CCAlgorithm(kCCAlgorithmAES128)
        }
    }

    func checkAESKeyLength(for key: Data) -> Bool {
        switch self {
        case .AES256CBCHS512:
            return key.count == kCCKeySizeAES256
        }
    }
}

internal struct AES {
    /// Encrypts a plain text using a given `AES` algorithm, the corresponding symmetric key and an initialization vector.
    ///
    /// - Parameters:
    ///   - plaintext: The plain text to encrypt.
    ///   - encryptionKey: The symmetric key.
    ///   - algorithm: The algorithm used to encrypt the plain text.
    ///   - initializationVector: The initial block.
    /// - Returns: The cipher text (encrypted plain text).
    /// - Throws:
    ///   - `EncryptionError.encryptingFailed(description: String)`: If the encryption failed with a specific error.
    ///   - `EncryptionError.keyLengthNotSatisfied`: If the encryption key length does not match the standards.
    static func encrypt(plaintext: Data, with encryptionKey: Data, using algorithm: SymmetricKeyAlgorithm, and initializationVector: Data) throws -> Data {
        switch algorithm {
        case .AES256CBCHS512:
            guard algorithm.checkAESKeyLength(for: encryptionKey) else {
                throw EncryptionError.keyLengthNotSatisfied
            }

            let encrypted = aes(operation: CCOperation(kCCEncrypt), data: plaintext, key: encryptionKey, algorithm: algorithm.ccAlgorithm, initializationVector: initializationVector, padding: CCOptions(kCCOptionPKCS7Padding))

            guard encrypted.status == UInt32(kCCSuccess) else {
                throw EncryptionError.encryptingFailed(description: "Encryption failed with status: \(encrypted.status).")
            }

            return encrypted.data
        }
    }

    /// Decrypts a cipher text using a given `AES` algorithm, the corresponding symmetric key and an initialization vector.
    ///
    /// - Parameters:
    ///   - cipherText: The encrypted cipher text to decrypt.
    ///   - decryptionKey: The symmetric key.
    ///   - algorithm: The algorithm used to decrypt the cipher text.
    ///   - initializationVector: The initial block.
    /// - Returns: The plain text (decrypted cipher text).
    /// - Throws:
    ///   - `EncryptionError.decryptingFailed(description: String)`: If the encryption failed with a specific error.
    ///   - `EncryptionError.keyLengthNotSatisfied`: If the encryption key length does not match the standards.
    static func decrypt(cipherText: Data, with decryptionKey: Data, using algorithm: SymmetricKeyAlgorithm, and initializationVector: Data) throws -> Data {
        switch algorithm {
        case .AES256CBCHS512:
            guard algorithm.checkAESKeyLength(for: decryptionKey) else {
                throw EncryptionError.keyLengthNotSatisfied
            }

            let decrypted = aes(operation: CCOperation(kCCDecrypt), data: cipherText, key: decryptionKey, algorithm: algorithm.ccAlgorithm, initializationVector: initializationVector, padding: CCOptions(kCCOptionPKCS7Padding))

            guard decrypted.status == UInt32(kCCSuccess) else {
                throw EncryptionError.decryptingFailed(description: "Decryption failed with CryptoStatus: \(decrypted.status).")
            }

            return decrypted.data
        }
    }

    static func aes(operation: CCOperation, data: Data, key: Data, algorithm: CCAlgorithm, initializationVector: Data, padding: CCOptions) -> (data: Data, status: UInt32) {
        let dataLength = data.count

        //AES's 128 block size is fix for every key length.
        let cryptLength  = size_t(dataLength + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)

        let keyLength = key.count
        var numBytesCrypted: size_t = 0

        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            data.withUnsafeBytes {dataBytes in
                initializationVector.withUnsafeBytes {ivBytes in
                    key.withUnsafeBytes {keyBytes in
                        CCCrypt(operation,
                                algorithm,
                                padding,
                                keyBytes, keyLength,
                                ivBytes,
                                dataBytes, dataLength,
                                cryptBytes, cryptLength,
                                &numBytesCrypted)
                    }
                }
            }
        }

        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.removeSubrange(numBytesCrypted..<cryptLength)
        }

        return (cryptData, UInt32(cryptStatus))
    }
}
