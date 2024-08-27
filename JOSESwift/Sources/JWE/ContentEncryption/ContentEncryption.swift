//
//  ContentEncryption.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//
//  ---------------------------------------------------------------------------
//  Copyright 2024 Airside Mobile Inc.
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

public protocol ContentEncrypter {
    var algorithm: ContentEncryptionAlgorithm { get }

    func encrypt(headerData: Data, payload: Payload, contentEncryptionKey: Data) throws -> ContentEncryptionContext
}

public protocol ContentDecrypter {
    var algorithm: ContentEncryptionAlgorithm { get }

    func decrypt(decryptionContext: ContentDecryptionContext) throws -> Data
}

public struct ContentEncryptionContext {
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

public struct ContentDecryptionContext {
    let ciphertext: Data
    let initializationVector: Data
    let additionalAuthenticatedData: Data
    let authenticationTag: Data
    let contentEncryptionKey: Data
}

extension ContentEncryptionAlgorithm {
    func makeContentEncrypter() throws -> ContentEncrypter {
        switch self {
        case .A128CBCHS256, .A192CBCHS384, .A256CBCHS512:
            return try AESCBCEncryption(contentEncryptionAlgorithm: self)
        case .A128GCM, .A192GCM, .A256GCM:
            return AESGCMEncryption(contentEncryptionAlgorithm: self)
        }
    }

    func makeContentDecrypter() throws -> ContentDecrypter {
        switch self {
        case .A128CBCHS256, .A192CBCHS384, .A256CBCHS512:
            return try AESCBCEncryption(contentEncryptionAlgorithm: self)
        case .A128GCM, .A192GCM, .A256GCM:
            return AESGCMEncryption(contentEncryptionAlgorithm: self)
        }
    }
}
