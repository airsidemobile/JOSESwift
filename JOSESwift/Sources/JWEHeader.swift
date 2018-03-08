//
//  JWEHeader.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12/10/2017.
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

/// The header of a `JWE` object.
public struct JWEHeader: JOSEHeader {
    let headerData: Data
    let parameters: [String: Any]

    /// Initializes a JWE header with given parameters and their original `Data` representation.
    /// Note that this (base64-url decoded) `Data` representation has to be exactly as it was
    /// received from the sender.
    ///
    /// - Parameters:
    ///   - parameters: The `Dictionary` representation of the `headerData` parameter.
    ///   - headerData: The (base64-url decoded) `Data` representation of the `parameters` parameter
    ///                 as it was received from the sender.
    /// - Throws: `HeaderParsingError` if the header cannot be created.
    init(parameters: [String: Any], headerData: Data) throws {
        guard JSONSerialization.isValidJSONObject(parameters) else {
            throw HeaderParsingError.headerIsNotValidJSONObject
        }

        guard parameters["alg"] is String else {
            throw HeaderParsingError.requiredHeaderParameterMissing(parameter: "alg")
        }

        guard parameters["enc"] is String else {
            throw HeaderParsingError.requiredHeaderParameterMissing(parameter: "enc")
        }

        self.headerData = headerData
        self.parameters = parameters
    }

    /// Initializes a `JWEHeader` with the specified algorithm and signing algorithm.
    public init(algorithm: AsymmetricKeyAlgorithm, encryptionAlgorithm: SymmetricKeyAlgorithm) {
        let parameters = [
            "alg": algorithm.rawValue,
            "enc": encryptionAlgorithm.rawValue
        ]

        // Forcing the try is ok here, since [String: String] can be converted to JSON.
        // swiftlint:disable:next force_try
        let headerData = try! JSONSerialization.data(withJSONObject: parameters, options: [])

        // Forcing the try is ok here, since "alg" and "enc" are the only required header parameters.
        // swiftlint:disable:next force_try
        try! self.init(parameters: parameters, headerData: headerData)
    }
}

// Header parameters that are specific to a JWE Header.
public extension JWEHeader {
    /// The algorithm used to encrypt or determine the value of the Content Encryption Key.
    public var algorithm: AsymmetricKeyAlgorithm? {
        // Forced cast is ok here since we checked both that "alg" exists
        // and holds a `String` value in `init(parameters:)`.
        // swiftlint:disable:next force_cast
        return AsymmetricKeyAlgorithm(rawValue: parameters["alg"] as! String)
    }

    /// The encryption algorithm used to perform authenticated encryption of the plaintext
    /// to produce the ciphertext and the Authentication Tag.
    public var encryptionAlgorithm: SymmetricKeyAlgorithm? {
        // Forced cast is ok here since we checked both that "enc" exists
        // and holds a `String` value in `init(parameters:)`.
        // swiftlint:disable:next force_cast
        return SymmetricKeyAlgorithm(rawValue: parameters["enc"] as! String)
    }
}

extension JWEHeader: CommonHeaderParameterSpace {
    /// The JWK Set URL which refers to a resource for a set of JSON-encoded public keys,
    /// one of which corresponds to the key used to encrypt the JWE.
    public var jku: URL? {
        return parameters["jku"] as? URL
    }

    /// The JSON Web key corresponding to the key used to encrypt the JWE.
    public var jwk: String? {
        return parameters["jwk"] as? String
    }

    /// The Key ID indicates the key which was used to encrypt the JWE.
    public var kid: String? {
        return parameters["kid"] as? String
    }

    /// The X.509 URL that referes to a resource for the X.509 public key certificate
    /// or certificate chain corresponding to the key used to encrypt the JWE.
    public var x5u: URL? {
        return parameters["x5u"] as? URL
    }

    /// The X.509 certificate chain contains the X.509 public key certificate or
    /// certificate chain corresponding to the key used to encrypt the JWE.
    public var x5c: [String: Any]? {
        return parameters["x5c"] as? [String: Any]
    }

    /// The X.509 certificate SHA-1 thumbprint of the DER encoding of the X.509 certificate
    /// corresponding to the key used to encrypt the JWE.
    public var x5t: String? {
        return parameters["x5t"] as? String
    }

    /// The X.509 certificate SHA-256 thumbprint of the DER encoding of the X.509 certificate
    /// corresponding to the key used to encrypt the JWE.
    public var x5tS256: String? {
        return parameters["x5tS256"] as? String
    }

    /// The type to declare the media type of the JWE object.
    public var typ: String? {
        return parameters["typ"] as? String
    }

    /// The content type to declare the media type of the secured content (payload).
    public var cty: String? {
        return parameters["cty"] as? String
    }

    /// The critical header parameter indicates the header parameter extensions.
    public var crit: [String]? {
        return parameters["crit"] as? [String]
    }
}
