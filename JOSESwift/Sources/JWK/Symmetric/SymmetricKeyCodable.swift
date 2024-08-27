//
//  SymmetricKeyCodable.swift
//  JOSESwift
//
//  Created by Daniel Egger on 10.07.18.
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

extension SymmetricKey: Encodable {
    public func encode(to encoder: Encoder) throws {
        var commonParameters = encoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        try commonParameters.encode(keyType, forKey: .keyType)

        // Other common parameters are optional.
        for parameter in parameters {
            // Only encode known parameters.
            if let key = JWKParameter(rawValue: parameter.key) {
                try commonParameters.encode(parameter.value, forKey: key)
            }
        }

        // Symmetric key specific parameters.
        var symmetricKeyParameters = encoder.container(keyedBy: SymmetricKeyParameter.self)
        try symmetricKeyParameters.encode(key, forKey: .key)
    }
}

extension SymmetricKey: Decodable {
    public init(from decoder: Decoder) throws {
        let commonParameters = try decoder.container(keyedBy: JWKParameter.self)

        // The key type parameter is required.
        guard try commonParameters.decode(String.self, forKey: .keyType) == JWKKeyType.OCT.rawValue else {
            throw DecodingError.keyNotFound(
                JWKParameter.keyType,
                DecodingError.Context.init(
                    codingPath: [JWKParameter.keyType],
                    debugDescription: "Wrong parameter: key type"
                )
            )
        }

        // Other common parameters are optional.
        var parameters: [String: String] = [:]
        for key in commonParameters.allKeys {
            parameters[key.rawValue] = try commonParameters.decode(String.self, forKey: key)
        }

        // RSA public key specific parameters.
        let symmetricKeyParameters = try decoder.container(keyedBy: SymmetricKeyParameter.self)
        let key = try symmetricKeyParameters.decode(String.self, forKey: .key)

        guard let keyData = Data(base64URLEncoded: key) else {
            throw JOSESwiftError.symmetricKeyNotBase64URLEncoded
        }

        self.init(key: keyData, additionalParameters: parameters)
    }
}
