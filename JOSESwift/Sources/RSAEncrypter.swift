//
//  AESEncrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 13/10/2017.
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

/// An `AsymmetricEncrypter` to encrypt plain text with an `RSA` algorithm.
internal struct RSAEncrypter: AsymmetricEncrypter {
    typealias KeyType = RSA.KeyType

    let algorithm: AsymmetricKeyAlgorithm
    let publicKey: KeyType?

    init(algorithm: AsymmetricKeyAlgorithm, publicKey: KeyType? = nil) {
        self.algorithm = algorithm
        self.publicKey = publicKey
    }

    func encrypt(_ plaintext: Data) throws -> Data {
        guard let publicKey = publicKey else {
            // If no key is set, we're using direct encryption so the encrypted key is empty.
            return Data()
        }

        return try RSA.encrypt(plaintext, with: publicKey, and: algorithm)
    }
}
