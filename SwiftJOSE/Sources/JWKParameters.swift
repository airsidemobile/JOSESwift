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

/// Possible common JWK parameters.
/// See [RFC-7517, Section 4](https://tools.ietf.org/html/rfc7517#section-4) for details.
public enum JWKParameter: String, CodingKey {
    case keyType = "kty"
    case keyUse = "use"
    case keyOperations = "key_ops"
    case algorithm = "alg"
    case keyIdentifier = "kid"
    case X509URL = "x5u"
    case X509CertificateChain = "x5c"
    case X509CertificateSHA1Thumbprint = "x5t"
    case X509CertificateSHA256Thumbprint = "x5t#S256"
}

/// RSA specific JWK parameters.
/// See [RFC-7518, Section 6.3](https://tools.ietf.org/html/rfc7518#section-6.3) for details.
public enum RSAParameter: String, CodingKey {
    case modulus = "n"
    case exponent = "e"
    case privateExponent = "d"
}
