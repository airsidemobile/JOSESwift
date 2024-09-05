//
//  AlgorithmExtensions.swift
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

extension ContentEncryptionAlgorithm {

    var keyLength: Int {
        switch self {
        case .A256CBCHS512:
            return 64
        case .A192CBCHS384:
            return 48
        case .A128CBCHS256, .A256GCM:
            return 32
        case .A192GCM:
            return 24
        case .A128GCM:
            return 16
        }
    }

    var initializationVectorLength: Int {
        switch self {
        case .A128CBCHS256, .A192CBCHS384, .A256CBCHS512:
            return 16
        case .A256GCM, .A192GCM, .A128GCM:
            return 12
        }
    }

    func checkKeyLength(for key: Data) -> Bool {
        return key.count == keyLength
    }

}

extension SignatureAlgorithm {
    var hmacAlgorithm: HMACAlgorithm? {
        switch self {
        case .HS256:
            return .SHA256
        case .HS384:
            return .SHA384
        case .HS512:
            return .SHA512
        default:
            return nil
        }
    }
}

extension KeyManagementAlgorithm {
    var hmacAlgorithm: HMACAlgorithm? {
        switch self {
        case .PBES2_HS256_A128KW:
            return .SHA256
        case .PBES2_HS384_A192KW:
            return .SHA384
        case .PBES2_HS512_A256KW:
            return .SHA512
        default:
            return nil
        }
    }

    var derivedKeyLength: Int? {
        switch self {
        case .PBES2_HS256_A128KW:
            return 16
        case .PBES2_HS384_A192KW:
            return 24
        case .PBES2_HS512_A256KW:
            return 32
        default:
            return nil
        }
    }
}
