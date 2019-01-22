//
//  JWKExtensions.swift
//  JOSESwift
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

// MARK: Subscript

public extension JWK {
    subscript(parameter: String) -> JWKParameterType? {
        return parameters[parameter]
    }
}

// MARK: Encoding Convenience Functions

public extension JWK {
    func jsonString() -> String? {
        guard let json = try? JSONEncoder().encode(self) else {
            return nil
        }

        return String(data: json, encoding: .utf8)
    }

    func jsonData() -> Data? {
        return try? JSONEncoder().encode(self)
    }
}

// MARK: Parameter getters

extension JWK {
    /// The public key use parameter identifies the intended use of a public key.
    /// See [RFC-7517](https://tools.ietf.org/html/rfc7517#section-4.2).
    var keyUse: String? {
        return parameters[JWKParameter.keyUse.rawValue] as? String
    }

    /// The key operations parameter identifies the operation(s) for which the key is intended to be used.
    /// See [RFC-7517](https://tools.ietf.org/html/rfc7517#section-4.3).
    var keyOperations: [String]? {
        return parameters[JWKParameter.keyOperations.rawValue] as? [String]
    }

    /// The algorithm parameter identifies the algorithm intended for use with the key.
    /// See [RFC-7517](https://tools.ietf.org/html/rfc7517#section-4.4).
    var algorithm: String? {
        return parameters[JWKParameter.algorithm.rawValue] as? String
    }

    /// The key identifier parameter is used to match a specific key.
    /// See [RFC-7517](https://tools.ietf.org/html/rfc7517#section-4.5).
    var keyIdentifier: String? {
        return parameters[JWKParameter.keyIdentifier.rawValue] as? String
    }

    /// The X.509 URL parameter is a URI that refers to a resource for an X.509 public key certificate
    /// or certificate chain.
    /// See [RFC-7517](https://tools.ietf.org/html/rfc7517#section-4.6).
    var X509URL: String? {
        return parameters[JWKParameter.X509URL.rawValue] as? String
    }

    /// The X.509 certificate chain parameter contains a chain of one or more PKIX certificates.
    /// See [RFC-7517](https://tools.ietf.org/html/rfc7517#section-4.7).
    var X509CertificateChain: [String]? {
        return parameters[JWKParameter.X509CertificateChain.rawValue] as? [String]
    }

    /// The X.509 certificate SHA-1 thumbprint parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest)
    /// of the DER encoding of an X.509 certificate.
    /// See [RFC-7517](https://tools.ietf.org/html/rfc7517#section-4.8).
    var X509CertificateSHA1Thumbprint: String? {
        return parameters[JWKParameter.X509CertificateSHA1Thumbprint.rawValue] as? String
    }

    /// The X.509 certificate SHA-256 thumbprint parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest)
    /// of the DER encoding of an X.509 certificate.
    /// See [RFC-7517](https://tools.ietf.org/html/rfc7517#section-4.9).
    var X509CertificateSHA256Thumbprint: String? {
        return parameters[JWKParameter.X509CertificateSHA256Thumbprint.rawValue] as? String
    }
}

