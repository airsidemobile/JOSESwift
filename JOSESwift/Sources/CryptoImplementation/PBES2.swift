//
//  PBES2.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 07.12.23.
//
//  ---------------------------------------------------------------------------
//  Copyright 2023 Airside Mobile Inc.
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

internal enum PBES2Error: Error {
    case unknownOrUnsupportedAlgorithm
}

internal struct PBES2 {
    static let defaultIterationCount = 1_000_000

    static func deriveWrappingKey(password: String, algorithm: KeyManagementAlgorithm, salt: Data, iterations: Int) throws -> Data {
		guard algorithm == .PBES2_HS256_A128KW || algorithm == .PBES2_HS384_A192KW || algorithm == .PBES2_HS512_A256KW else {
			throw PBES2Error.unknownOrUnsupportedAlgorithm
		}
        guard let hmacAlgorithm = algorithm.hmacAlgorithm else {
            throw HMACError.algorithmNotSupported
        }

        let passwordData = password.data(using: .utf8)!
        let algorithmData = algorithm.rawValue.data(using: .utf8)!
        let saltData = algorithmData + Data([0x00]) + salt

        var derivedKey = Data(count: algorithm.keyLength)
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            saltData.withUnsafeBytes { saltBytes in
                passwordData.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress!,
                        passwordData.count,
                        saltBytes.baseAddress!,
                        saltData.count,
                        hmacAlgorithm.ccPseudoRandomAlgorithm,
                        UInt32(iterations),
                        derivedKeyBytes.baseAddress!,
                        derivedKeyBytes.count
                    )
                }
            }
        }

        if (result == kCCSuccess) {
            return derivedKey
        } else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(result), userInfo: nil)
        }
    }
}
