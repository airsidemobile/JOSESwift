//
//  AESDecrypter.swift
//  JOSESwift
//
//  Created by Daniel Egger on 19/10/2017.
//  Refactored by Marius Tamulis on 2019-03-12.
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
internal struct RSADecrypter: KeyDecrypter {
    typealias KeyType = RSA.KeyType

    var algorithm: KeyAlgorithm {
        return rsaAlgorithm
    }
    private var rsaAlgorithm: AsymmetricKeyAlgorithm

    var key: Any? {
        return privateKey
    }
    private var privateKey: KeyType?

    init(algorithm: AsymmetricKeyAlgorithm, privateKey: KeyType? = nil) {
        self.rsaAlgorithm = algorithm
        self.privateKey = privateKey
    }

    func decrypt(_ ciphertext: Data) throws -> Data {
        guard let privateKey = privateKey, rsaAlgorithm != .direct else {
            // If no key is set, we're using direct encryption so the encrypted key is empty.
            return Data()
        }

        return try RSA.decrypt(ciphertext, with: privateKey, and: rsaAlgorithm)
    }
}
