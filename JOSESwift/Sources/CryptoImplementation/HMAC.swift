//
//  HMAC.swift
//  JOSESwift
//
//  Created by Carol Capek on 05.12.17.
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

fileprivate extension HMACAlgorithm {
    var ccAlgorithm: CCAlgorithm {
        switch self {
        case .SHA512:
            return CCAlgorithm(kCCHmacAlgSHA512)
        }
    }
}

internal struct HMAC {
    /// Calculates a HMAC of an input with a specific HMAC algorithm and the corresponding HMAC key.
    ///
    /// - Parameters:
    ///   - input: The input to calculate a HMAC for.
    ///   - key: The key used in the HMAC algorithm.
    ///   - algorithm: The algorithm used to calculate the HMAC.
    /// - Returns: The calculated HMAC.
    static func calculate(from input: Data, with key: Data, using algorithm: HMACAlgorithm) -> Data {
        var hmacOutData = Data(count: algorithm.outputLength)

        hmacOutData.withUnsafeMutableBytes { hmacOutBytes in
            key.withUnsafeBytes { keyBytes in
                input.withUnsafeBytes { inputBytes in
                    CCHmac(algorithm.ccAlgorithm, keyBytes, key.count, inputBytes, input.count, hmacOutBytes)
                }
            }
        }

        return hmacOutData
    }
}
