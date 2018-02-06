//
//  Algorithms.swift
//  SwiftJOSE
//
//  Created by Carol Capek on 06.02.18.
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

/// An algorithm for signing and verifying
///
/// - RSA
public enum SignatureAlgorithm: String {
    case RS512 = "RS512"

    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .RS512:
            return .rsaSignatureMessagePKCS1v15SHA512
        }
    }
}

/// An algorithm for asymmetric encryption and decryption
///
/// - RSAPKCS
public enum AsymmetricKeyAlgorithm: String {
    case RSAPKCS = "RSA1_5"

    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .RSAPKCS:
            return .rsaEncryptionPKCS1
        }
    }

    /// Checks if the plain text length does not exceed the maximum
    /// for the chosen algorithm and the corresponding public key.
    func isPlainTextLengthSatisfied(_ plainText: Data, for publicKey: SecKey) -> Bool {
        switch self {
        case .RSAPKCS:
            // For detailed information about the allowed plain text length for RSAES-PKCS1-v1_5,
            // please refer to the RFC(https://tools.ietf.org/html/rfc3447#section-7.2).
            return plainText.count < (SecKeyGetBlockSize(publicKey) - 11)
        }
    }

    func isCipherTextLenghtSatisfied(_ cipherText: Data, for privateKey: SecKey) -> Bool {
        switch self {
        case .RSAPKCS:
            return cipherText.count == SecKeyGetBlockSize(privateKey)
        }
    }
}

/// An algorithm for symmetric encryption and decryption
///
/// - AES256CBCHS512
public enum SymmetricKeyAlgorithm: String {
    case AES256CBCHS512 = "A256CBC-HS512"

    var hmacAlgorithm: HMACAlgorithm {
        switch self {
        case .AES256CBCHS512:
            return .SHA512
        }
    }

    func keyLength() -> Int {
        switch self {
        case .AES256CBCHS512:
            return 64
        }
    }

    func initializationVectorLength() -> Int {
        switch self {
        case .AES256CBCHS512:
            return 16
        }
    }

    func checkKeyLength(for key: Data) -> Bool {
        switch self {
        case .AES256CBCHS512:
            return key.count == 64
        }
    }

    func retrieveKeys(from inputKey: Data) throws -> (hmacKey: Data, encryptionKey: Data) {
        switch self {
        case .AES256CBCHS512:
            guard checkKeyLength(for: inputKey) else {
                throw EncryptionError.keyLengthNotSatisfied
            }

            return (inputKey.subdata(in: 0..<32), inputKey.subdata(in: 32..<64))
        }
    }

    func authenticationTag(for hmac: Data) -> Data {
        switch self {
        case .AES256CBCHS512:
            return hmac.subdata(in: 0..<32)
        }
    }
}

/// An algorithm for HMAC calculation
///
/// - SHA512
public enum HMACAlgorithm: String {
    case SHA512 = "SHA512"

    var outputLength: Int {
        switch self {
        case .SHA512:
            return 64
        }
    }
}
