//
//  RSAKeys.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
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

public struct RSAPublicKey: PublicKey {
    public let keyType: JWKKeyType
    public let parameters: [String: Any]

    public let modulus: String
    public let exponent: String

    init(modulus: String, exponent: String, additionalParameters parameters: [String: Any] = [:]) {
        self.keyType = .RSA
        self.modulus = modulus
        self.exponent = exponent

        self.parameters = parameters.merging(
            zip(
                [ JWKKeyType.parameterName, "n", "e" ],
                [ self.keyType.rawValue, self.modulus, self.exponent ]
            ),
            uniquingKeysWith: { (_, new) in new }
        )
    }
}

public struct RSAPrivateKey: PrivateKey, KeyPair {
    public let keyType: JWKKeyType
    public let parameters: [String: Any]

    public let modulus: String
    public let exponent: String
    public let privateExponent: String

    init(modulus: String, exponent: String, privateExponent: String, additionalParameters parameters: [String: Any] = [:]) {
        self.keyType = .RSA
        self.modulus = modulus
        self.exponent = exponent
        self.privateExponent = privateExponent

        self.parameters = parameters.merging(
            zip(
                [ JWKKeyType.parameterName, "n", "e", "d" ],
                [ self.keyType.rawValue, self.modulus, self.exponent, self.privateExponent ]
            ),
            uniquingKeysWith: { (_, new) in new }
        )
    }
}

public typealias RSAKeyPair = RSAPrivateKey
