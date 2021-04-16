//
//  HMAC.swift
//  JOSESwift
//
//  Created by Carol Capek on 05.12.17.
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
import CommonCrypto

enum HMACError: Error {
    case algorithmNotSupported
    case inputMustBeGreaterThanZero
}

fileprivate extension HMACAlgorithm {
    var ccAlgorithm: CCAlgorithm {
        switch self {
        case .SHA512:
            return CCAlgorithm(kCCHmacAlgSHA512)
        case .SHA384:
            return CCAlgorithm(kCCHmacAlgSHA384)
        case .SHA256:
            return CCAlgorithm(kCCHmacAlgSHA256)
        }
    }
}

internal struct HMAC {
    typealias KeyType = Data

    /// Calculates a HMAC of an input with a specific HMAC algorithm and the corresponding HMAC key.
    ///
    /// - Parameters:
    ///   - input: The input to calculate a HMAC for.
    ///   - key: The key used in the HMAC algorithm. Must not be empty.
    ///   - algorithm: The algorithm used to calculate the HMAC.
    /// - Returns: The calculated HMAC.
    static func calculate(from input: Data, with key: Data, using algorithm: HMACAlgorithm) throws -> Data {
        guard input.count > 0 else {
            throw HMACError.inputMustBeGreaterThanZero
        }

        var hmacOutData = Data(count: algorithm.outputLength)

        // Force unwrapping is ok, since input count is checked and key and algorithm are assumed not to be empty.
        // From the docs: If the baseAddress of this buffer is nil, the count is zero.
        // swiftlint:disable force_unwrapping
        hmacOutData.withUnsafeMutableBytes { hmacOutBytes in
            key.withUnsafeBytes { keyBytes in
                input.withUnsafeBytes { inputBytes in
                    CCHmac(
                        algorithm.ccAlgorithm,
                        keyBytes.baseAddress!, key.count,
                        inputBytes.baseAddress!, input.count,
                        hmacOutBytes.baseAddress!
                    )
                }
            }
        }
        // swiftlint:enable force_unwrapping

        return hmacOutData
    }
}
