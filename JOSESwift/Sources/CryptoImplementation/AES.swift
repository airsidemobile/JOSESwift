//
//  AES.swift
//  JOSESwift
//
//  Created by Carol Capek on 04.01.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
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
import CommonCrypto

internal enum AESError: Error {
    case keyLengthNotSatisfied
    case encryptingFailed(description: String)
    case decryptingFailed(description: String)
    case cannotPerformOperationOnEmptyDataBuffer
    case invalidAlgorithm
}

fileprivate extension ContentEncryptionAlgorithm {
    var ccAlgorithm: CCAlgorithm {
        switch self {
        case .A256CBCHS512:
            return CCAlgorithm(kCCAlgorithmAES128)

        case .A128CBCHS256:
            return CCAlgorithm(kCCAlgorithmAES128)
        }
    }

    func checkAESKeyLength(for key: Data) -> Bool {
        switch self {
        case .A256CBCHS512:
            return key.count == kCCKeySizeAES256

        case .A128CBCHS256:
            return key.count == kCCKeySizeAES128
        }
    }
}

fileprivate extension KeyManagementAlgorithm {
    var ccAlgorithm: CCAlgorithm? {
        switch self {
        case .A128KW, .A192KW, .A256KW:
            return CCAlgorithm(kCCAlgorithmAES)
        default:
            return nil
        }
    }

    var iv: Data? {
        switch self {
        case .A128KW, .A192KW, .A256KW:
            // See https://tools.ietf.org/html/rfc3394#section-2.2.3.1
            // The default iv is defined to be the hexadecimal constant A6A6A6A6A6A6A6A6
            // Todo: Check actual runtime value
            return Data(bytes: CCrfc3394_iv, count: CCrfc3394_ivLen)
        default:
            return nil
        }
    }

    func checkAESKeyLength(for key: Data) -> Bool? {
        switch self {
        case .A128KW:
            return key.count == kCCKeySizeAES128
        case .A192KW:
            return key.count == kCCKeySizeAES192
        case .A256KW:
            return key.count == kCCKeySizeAES256
        default:
            return nil
        }
    }
}

enum AES {
    typealias KeyType = Data

    /// Encrypts a plain text using a given `AES` algorithm, the corresponding symmetric key and an initialization vector.
    ///
    /// - Parameters:
    ///   - plaintext: The plain text to encrypt.
    ///   - encryptionKey: The symmetric key.
    ///   - algorithm: The algorithm used to encrypt the plain text.
    ///   - initializationVector: The initial block.
    /// - Returns: The cipher text (encrypted plain text).
    /// - Throws: `AESError` if any error occurs during encryption.
    static func encrypt(
        _ plaintext: Data,
        with encryptionKey: KeyType,
        using algorithm: ContentEncryptionAlgorithm,
        and initializationVector: Data
    ) throws -> Data {
        switch algorithm {
        case .A256CBCHS512, .A128CBCHS256:
            guard algorithm.checkAESKeyLength(for: encryptionKey) else {
                throw AESError.keyLengthNotSatisfied
            }

            let encrypted = try ccAESCBCCrypt(
                operation: CCOperation(kCCEncrypt),
                data: plaintext, key: encryptionKey,
                algorithm: algorithm.ccAlgorithm,
                initializationVector: initializationVector,
                padding: CCOptions(kCCOptionPKCS7Padding)
            )

            guard encrypted.status == UInt32(kCCSuccess) else {
                throw AESError.encryptingFailed(description: "Encryption failed with status: \(encrypted.status).")
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
    /// - Throws: `AESError` if any error occurs during decryption.
    static func decrypt(
        cipherText: Data,
        with decryptionKey: Data,
        using algorithm: ContentEncryptionAlgorithm,
        and initializationVector: Data
    ) throws -> Data {
        switch algorithm {
        case .A256CBCHS512, .A128CBCHS256:
            guard algorithm.checkAESKeyLength(for: decryptionKey) else {
                throw AESError.keyLengthNotSatisfied
            }

            let decrypted = try ccAESCBCCrypt(
                operation: CCOperation(kCCDecrypt),
                data: cipherText, key: decryptionKey,
                algorithm: algorithm.ccAlgorithm,
                initializationVector: initializationVector,
                padding: CCOptions(kCCOptionPKCS7Padding)
            )

            guard decrypted.status == UInt32(kCCSuccess) else {
                throw AESError.decryptingFailed(description: "Decryption failed with CryptoStatus: \(decrypted.status).")
            }

            return decrypted.data
        }
    }

    static func keyWrap(rawKey: Data, keyEncryptionKey: Data, algorithm: KeyManagementAlgorithm) throws -> Data {
        switch algorithm {
        case .A128KW, .A192KW, .A256KW:
            // Todo: Better solve this invalid algorithm problem
            guard algorithm.checkAESKeyLength(for: keyEncryptionKey)! else {
                throw AESError.keyLengthNotSatisfied
            }

            let iv = algorithm.iv!

            let wrapped = try ccAESKeyWrap(rawKey: rawKey, keyEncryptionKey: keyEncryptionKey, iv: iv)

            guard wrapped.status == kCCSuccess else {
                throw AESError.encryptingFailed(description: "Key wrap failed with CryptoStatus: \(wrapped.status).")
            }

            return wrapped.data
        default:
            throw AESError.invalidAlgorithm
        }
    }
}

extension AES {
    // swiftlint:disable:next function_parameter_count
    private static func ccAESCBCCrypt(
        operation: CCOperation,
        data: Data,
        key: Data,
        algorithm: CCAlgorithm,
        initializationVector: Data,
        padding: CCOptions
    ) throws -> (data: Data, status: UInt32) {
        let dataLength = data.count
        let keyLength = key.count
        let ivLength = initializationVector.count

        guard dataLength > 0, keyLength > 0, ivLength > 0 else {
            throw AESError.cannotPerformOperationOnEmptyDataBuffer
        }

        // AES's 128 block size is fixed for every key length and guaranteed not to be 0.
        let cryptLength  = size_t(dataLength + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)

        var numBytesCrypted: size_t = 0

        // Force unwrapping is ok, since buffers are guaranteed not to be empty.
        // From the docs: If the baseAddress of this buffer is nil, the count is zero.
        // swiftlint:disable force_unwrapping
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                initializationVector.withUnsafeBytes { ivBytes in
                    key.withUnsafeBytes { keyBytes in
                        CCCrypt(operation,
                                algorithm,
                                padding,
                                keyBytes.baseAddress!, keyLength,
                                ivBytes.baseAddress!,
                                dataBytes.baseAddress!, dataLength,
                                cryptBytes.baseAddress!, cryptLength,
                                &numBytesCrypted)
                    }
                }
            }
        }
        // swiftlint:enable force_unwrapping

        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.removeSubrange(numBytesCrypted..<cryptLength)
        }

        return (cryptData, UInt32(cryptStatus))
    }
}

extension AES {
    private static func ccAESKeyWrap(
        rawKey: Data,
        keyEncryptionKey: Data,
        iv: Data
    ) throws -> (data: Data, status: Int32) {
        let alg = CCWrappingAlgorithm(kCCWRAPAES)

        var wrappedKeyLength: size_t = CCSymmetricWrappedSize(alg, rawKey.count)
        var wrappedKey = Data(count: wrappedKeyLength)

        guard wrappedKey.count > 0, rawKey.count > 0, iv.count > 0, keyEncryptionKey.count > 0 else {
            throw AESError.cannotPerformOperationOnEmptyDataBuffer
        }

        let status = wrappedKey.withUnsafeMutableBytes { wrappedKeyBytes in
            rawKey.withUnsafeBytes { rawKeyBytes in
                iv.withUnsafeBytes { ivBytes in
                    keyEncryptionKey.withUnsafeBytes { keyEncryptionKeyBytes -> Int32 in
                        guard
                            let wrappedKeyBytes = wrappedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                            let rawKeyBytes = rawKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                            let ivBytes = ivBytes.bindMemory(to: UInt8.self).baseAddress,
                            let keyEncryptionKeyBytes = keyEncryptionKeyBytes.bindMemory(to: UInt8.self).baseAddress
                        else {
                            return Int32(kCCMemoryFailure)
                        }
                        return CCSymmetricKeyWrap(
                            alg,
                            ivBytes, iv.count,
                            keyEncryptionKeyBytes, keyEncryptionKey.count,
                            rawKeyBytes, rawKey.count,
                            wrappedKeyBytes, &wrappedKeyLength
                        )
                    }
                }
            }
        }

        if status == kCCSuccess {
            wrappedKey.removeSubrange(wrappedKeyLength..<wrappedKey.count)
        }

        return (wrappedKey, status)
    }
}
