//
//  AESDecrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 19/10/2017.
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

/// An `AsymmetricDecrypter` to decrypt cipher text with a `RSA` algorithm.
internal struct RSADecrypter: AsymmetricDecrypter {
    typealias KeyType = RSA.KeyType

    let algorithm: AsymmetricKeyAlgorithm
    let privateKey: KeyType?

    init(algorithm: AsymmetricKeyAlgorithm, privateKey: KeyType? = nil) {
        self.algorithm = algorithm
        self.privateKey = privateKey
    }

    func decrypt(_ ciphertext: Data) throws -> Data {
        guard let privateKey = privateKey else {
            // If no key is set, we're using direct encryption so the encrypted key is empty.
            return Data()
        }

        return try RSA.decrypt(ciphertext, with: privateKey, and: algorithm)
    }
}
