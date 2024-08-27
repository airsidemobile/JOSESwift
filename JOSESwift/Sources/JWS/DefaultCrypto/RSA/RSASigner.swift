//
//  RSASigner.swift
//  JOSESwift
//
//  Created by Daniel Egger on 21/08/2017.
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

/// A `Signer` to sign an input with an `RSA` algorithm.
internal struct RSASigner: SignerProtocol {
    typealias KeyType = RSA.KeyType

    let algorithm: SignatureAlgorithm
    let privateKey: KeyType

    func sign(_ signingInput: Data) throws -> Data {
        return try RSA.sign(signingInput, with: privateKey, and: algorithm)
    }
}
