//
//  HMACVerifier.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 14.04.21.
//
//  ---------------------------------------------------------------------------
//  Copyright 2021 Airside Mobile Inc.
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

/// A `Verifier` to verify a signature created with an `HMAC` algorithm.
internal struct HMACVerifier: VerifierProtocol {
    typealias KeyType = HMAC.KeyType

    let algorithm: SignatureAlgorithm
    let key: KeyType

    func verify(_ signingInput: Data, against signature: Data) throws -> Bool {
        guard let hmacAlgorithm = algorithm.hmacAlgorithm else {
            throw HMACError.algorithmNotSupported
        }
        let hmacOutput = try HMAC.calculate(from: signingInput, with: key, using: hmacAlgorithm)
        return hmacOutput.timingSafeCompare(with: signature)
    }
}
