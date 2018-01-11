//
//  JWKParameters.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21.12.17.
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

/// The key type parameter of a JWK identifies the cryptographic algorithm
/// family used with the key(s) represented by a JWK.
/// See [RFC-7518](https://tools.ietf.org/html/rfc7518#section-7.4) for details.
///
/// - RSA
public enum JWKKeyType: String {
    case RSA = "RSA"

    var parameterName: String {
        return "kty"
    }
}

// Todo: Add more JWK parameters here. See https://tools.ietf.org/html/rfc7517#section-4.
