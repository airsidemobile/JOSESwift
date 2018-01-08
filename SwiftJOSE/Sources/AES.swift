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
import CommonCrypto

fileprivate extension SymmetricEncryptionAlgorithm {
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

public struct AES {

    public static func encrypt(plaintext: Data, encryptionKey: Data, algorithm: SymmetricEncryptionAlgorithm, iv: Data) -> Data {
        switch algorithm {
        case .AES256CBCHS512:
            encrypt256(plaintext: plaintext, encryptionKey: encryptionKey, iv: iv)
        }
    }

    public static func encrypt256(plaintext: Data, encryptionKey: Data, iv: Data) -> Data {
        let dataLength = plaintext.count

    fileprivate static func aes(operation: CCOperation, data: Data, key: Data, algorithm: CCAlgorithm, initializationVector: Data, padding: CCOptions) -> (data: Data, status: UInt32) {
        let dataLength = data.count

        //AES's 128 block size is fix for every key length.
        let cryptLength  = size_t(dataLength + kCCBlockSizeAES128)
        var cryptData = Data(count:cryptLength)

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
