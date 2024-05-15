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
            return CCAlgorithm(kCCAlgorithmAES)

        case .A128CBCHS256:
            return CCAlgorithm(kCCAlgorithmAES)
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

extension KeyManagementAlgorithm {
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

    var keyBitSize: Int? {
        switch self {
        case .A128KW:
            return 128
        case .A192KW:
            return 192
        case .A256KW:
            return 256
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

            let encrypted = ccAESCBCCrypt(
                operation: CCOperation(kCCEncrypt),
                data: plaintext, key: encryptionKey,
                algorithm: algorithm.ccAlgorithm,
                initializationVector: initializationVector,
                padding: CCOptions(kCCOptionPKCS7Padding)
            )

            guard
                let ciphertext = encrypted.data,
                encrypted.status == UInt32(kCCSuccess)
            else {
                throw AESError.encryptingFailed(description: "Encryption failed with status: \(encrypted.status).")
            }

            return ciphertext
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

            let decrypted = ccAESCBCCrypt(
                operation: CCOperation(kCCDecrypt),
                data: cipherText, key: decryptionKey,
                algorithm: algorithm.ccAlgorithm,
                initializationVector: initializationVector,
                padding: CCOptions(kCCOptionPKCS7Padding)
            )

            guard
                let plaintext = decrypted.data,
                decrypted.status == UInt32(kCCSuccess)
            else {
                throw AESError.decryptingFailed(description: "Decryption failed with status: \(decrypted.status).")
            }

            return plaintext
        }
    }

    /// Encrypts the given raw key using AES key wrap.
    /// - Parameters:
    ///   - rawKey: The raw key to encrypt
    ///   - keyEncryptionKey: The key used to encypt the raw key
    ///   - algorithm: The algorithm to use for AES key wrap
    static func wrap(rawKey: Data, keyEncryptionKey: Data, algorithm: KeyManagementAlgorithm) throws -> Data {
        let keyWrapAlgorithms: [KeyManagementAlgorithm] = [.A128KW, .A192KW, .A256KW]

        guard keyWrapAlgorithms.contains(algorithm) else {
            throw AESError.invalidAlgorithm
        }

        guard algorithm.checkAESKeyLength(for: keyEncryptionKey) == true else {
            throw AESError.keyLengthNotSatisfied
        }

        let wrapped = ccAESKeyWrap(rawKey: rawKey, keyEncryptionKey: keyEncryptionKey)

        guard let wrappedKey = wrapped.data, wrapped.status == kCCSuccess else {
            throw AESError.encryptingFailed(description: "Key wrap failed with status: \(wrapped.status).")
        }

        return wrappedKey
    }

    /// Decrypts the given raw key using AES key wrap.
    /// - Parameters:
    ///   - rawKey: The raw key to decrypt
    ///   - keyEncryptionKey: The key that was used to encrypt the raw key
    ///   - algorithm: The algorithm to use for AES key wrap
    static func unwrap(wrappedKey: Data, keyEncryptionKey: Data, algorithm: KeyManagementAlgorithm) throws -> Data {
        let keyWrapAlgorithms: [KeyManagementAlgorithm] = [.A128KW, .A192KW, .A256KW]

        guard keyWrapAlgorithms.contains(algorithm) else {
            throw AESError.invalidAlgorithm
        }

        guard algorithm.checkAESKeyLength(for: keyEncryptionKey) == true else {
            throw AESError.keyLengthNotSatisfied
        }

        let unwrapped = ccAESKeyUnwrap(wrappedKey: wrappedKey, keyEncryptionKey: keyEncryptionKey)

        guard let unwrappedKey = unwrapped.data, unwrapped.status == kCCSuccess else {
            throw AESError.decryptingFailed(description: "Key unwrap failed with status: \(unwrapped.status).")
        }

        return unwrappedKey
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
    ) -> (data: Data?, status: Int32) {
        let dataLength = data.count
        let keyLength = key.count
        let ivLength = initializationVector.count

        guard dataLength > 0, keyLength > 0, ivLength > 0 else {
            return (nil, CCCryptorStatus(kCCParamError))
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
                    key.withUnsafeBytes { keyBytes -> Int32 in
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

        guard cryptStatus == kCCSuccess else {
            return (nil, cryptStatus)
        }

        cryptData.removeSubrange(numBytesCrypted..<cryptLength)

        return (cryptData, cryptStatus)
    }
}

extension AES {
    private static func ccAESKeyWrap(
        rawKey: Data,
        keyEncryptionKey: Data) -> (data: Data?, status: Int32) {

        let alg = CCWrappingAlgorithm(kCCWRAPAES)
        var wrappedKeyLength: size_t = CCSymmetricWrappedSize(alg, rawKey.count)
        var wrappedKey = Data(count: wrappedKeyLength)

        let status = wrappedKey.withUnsafeMutableBytes { wrappedKeyBytes in
            rawKey.withUnsafeBytes { rawKeyBytes in
                keyEncryptionKey.withUnsafeBytes { keyEncryptionKeyBytes -> Int32 in
                    guard
                        let wrappedKeyBytes = wrappedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        let rawKeyBytes = rawKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        let keyEncryptionKeyBytes = keyEncryptionKeyBytes.bindMemory(to: UInt8.self).baseAddress
                    else {
                        return Int32(kCCMemoryFailure)
                    }
                    return CCSymmetricKeyWrap(
                        alg,
                        CCrfc3394_iv,
                        CCrfc3394_ivLen,
                        keyEncryptionKeyBytes,
                        keyEncryptionKey.count,
                        rawKeyBytes, rawKey.count,
                        wrappedKeyBytes, &wrappedKeyLength)
                }
            }
        }

        guard status == kCCSuccess else {
            return (nil, status)
        }

        wrappedKey.removeSubrange(wrappedKeyLength..<wrappedKey.count)
        return (wrappedKey, status)
    }

    private static func ccAESKeyUnwrap(
        wrappedKey: Data,
        keyEncryptionKey: Data) -> (data: Data?, status: Int32) {

        let alg = CCWrappingAlgorithm(kCCWRAPAES)

        var rawKeyLength: size_t = CCSymmetricUnwrappedSize(alg, wrappedKey.count)
        var rawKey = Data(count: rawKeyLength)

        let status = rawKey.withUnsafeMutableBytes { rawKeyBytes in
            wrappedKey.withUnsafeBytes { wrappedKeyBytes in
                keyEncryptionKey.withUnsafeBytes { keyEncryptionKeyBytes -> Int32 in
                    guard
                        let rawKeyBytes = rawKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        let wrappedKeyBytes = wrappedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        let keyEncryptionKeyBytes = keyEncryptionKeyBytes.bindMemory(to: UInt8.self).baseAddress
                    else {
                        return Int32(kCCMemoryFailure)
                    }
                    return CCSymmetricKeyUnwrap(
                            alg,
                            CCrfc3394_iv,
                            CCrfc3394_ivLen,
                            keyEncryptionKeyBytes,
                            keyEncryptionKey.count,
                            wrappedKeyBytes,
                            wrappedKey.count,
                            rawKeyBytes,
                            &rawKeyLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            return (nil, status) // kCCDecodeError
        }

        rawKey.removeSubrange(rawKeyLength..<rawKey.count)
        return (rawKey, status)
    }
}
