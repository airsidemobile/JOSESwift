//
//  ContentEncryption.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//
//  ---------------------------------------------------------------------------
//  Copyright 2020 Airside Mobile Inc.
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

struct ContentEncryptionContext {
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

struct ContentDecryptionContext {
    let ciphertext: Data
    let initializationVector: Data
    let additionalAuthenticatedData: Data
    let authenticationTag: Data
}

protocol ContentEncrypter {
    func encrypt(header: JWEHeader, payload: Payload) throws -> ContentEncryptionContext
}

protocol ContentDecrypter {
    func decrypt(decryptionContext: ContentDecryptionContext) throws -> Data
}

extension ContentEncryptionAlgorithm {
    func makeContentEncrypter(contentEncryptionKey: Data) -> ContentEncrypter {
        switch self {
        case .A128CBCHS256, .A256CBCHS512:
            return AESCBCEncryption(contentEncryptionAlgorithm: self, contentEncryptionKey: contentEncryptionKey)
        }
    }

    func makeContentDecrypter(contentEncryptionKey: Data) -> ContentDecrypter {
        switch self {
        case .A128CBCHS256, .A256CBCHS512:
            return AESCBCEncryption(contentEncryptionAlgorithm: self, contentEncryptionKey: contentEncryptionKey)
        }
    }
}
