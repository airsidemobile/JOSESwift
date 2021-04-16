//
//  AlgorithmExtensions.swift
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

extension ContentEncryptionAlgorithm {
    var hmacAlgorithm: HMACAlgorithm {
           switch self {
           case .A256CBCHS512:
               return .SHA512
           case .A128CBCHS256:
               return .SHA256
           }
       }

       var keyLength: Int {
           switch self {
           case .A256CBCHS512:
               return 64
           case .A128CBCHS256:
               return 32
           }
       }

       var initializationVectorLength: Int {
           switch self {
           case .A128CBCHS256, .A256CBCHS512:
               return 16
           }
       }

       func checkKeyLength(for key: Data) -> Bool {
           switch self {
           case .A256CBCHS512:
               return key.count == 64
           case .A128CBCHS256:
               return key.count == 32
           }
       }

       func retrieveKeys(from inputKey: Data) throws -> (hmacKey: Data, encryptionKey: Data) {
           switch self {
           case .A256CBCHS512:
               guard checkKeyLength(for: inputKey) else {
                   throw JWEError.keyLengthNotSatisfied
               }

               return (inputKey.subdata(in: 0..<32), inputKey.subdata(in: 32..<64))

           case .A128CBCHS256:
               guard checkKeyLength(for: inputKey) else {
                   throw JWEError.keyLengthNotSatisfied
               }
               return (inputKey.subdata(in: 0..<16), inputKey.subdata(in: 16..<32))
           }
       }

       func authenticationTag(for hmac: Data) -> Data {
           switch self {
           case .A256CBCHS512:
               return hmac.subdata(in: 0..<32)
           case .A128CBCHS256:
               return hmac.subdata(in: 0..<16)
           }
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
