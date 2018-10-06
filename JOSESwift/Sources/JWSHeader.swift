//
//  JWSHeader.swift
//  JOSESwift
//
//  Created by Daniel Egger on 27/09/2017.
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

/// The header of a `JWS` object.
public struct JWSHeader: JOSEHeader {
    var headerData: Data
    var parameters: [String: Any] {
        didSet {
            guard JSONSerialization.isValidJSONObject(parameters) else {
                return
            }
            // Forcing the try is ok here, because it is valid JSON.
            // swiftlint:disable:next force_try
            headerData = try! JSONSerialization.data(withJSONObject: parameters, options: [])
        }
    }

    /// Initializes a JWS header with given parameters and their original `Data` representation.
    /// Note that this (base64-url decoded) `Data` representation has to be exactly as it was
    /// received from the sender in order to guarantee correctness of signature validations.
    ///
    /// - Parameters:
    ///   - parameters: The `Dictionary` representation of the `headerData` parameter.
    ///   - headerData: The (base64-url decoded) `Data` representation of the `parameters` parameter
    ///                 as it was received from the sender.
    /// - Throws: `HeaderParsingError` if the header cannot be created.
    internal init(parameters: [String: Any], headerData: Data) throws {
        guard JSONSerialization.isValidJSONObject(parameters) else {
            throw HeaderParsingError.headerIsNotValidJSONObject
        }

        // Verify that the implementation understands and can process all
        // fields that it is required to support.
        guard parameters["alg"] is String else {
            throw HeaderParsingError.requiredHeaderParameterMissing(parameter: "alg")
        }

        self.headerData = headerData
        self.parameters = parameters
    }

    /// Initializes a `JWSHeader` with the specified algorithm.
    public init(algorithm: SignatureAlgorithm) {
        let parameters = ["alg": algorithm.rawValue]
        // Forcing the try is ok here, since [String: String] can be converted to JSON.
        // swiftlint:disable:next force_try
        let headerData = try! JSONSerialization.data(withJSONObject: parameters, options: [])

        // Forcing the try is ok here, since "alg" is the only required header parameter.
        // swiftlint:disable:next force_try
        try! self.init(parameters: parameters, headerData: headerData)
    }
}

// Header parameters that are specific to a JWS Header.
extension JWSHeader {
    /// The algorithm used to sign the payload.
    public var algorithm: SignatureAlgorithm? {
        // Forced cast is ok here since we checked both that "alg" exists
        // and holds a `String` value in `init(parameters:)`
        // swiftlint:disable:next force_cast
        return SignatureAlgorithm(rawValue: parameters["alg"] as! String)
    }
}

extension JWSHeader: CommonHeaderParameterSpace {
    /// The JWK Set URL which refers to a resource for a set of JSON-encoded public keys,
    /// one of which corresponds to the key used to sign the JWS.
    public var jku: URL? {
        set {
            parameters["jku"] = newValue?.absoluteString
        }
        get {
            guard let parameter = parameters["jku"] as? String else {
                return nil
            }
            return URL(string: parameter)
        }
    }

    /// The JSON Web key corresponding to the key used to digitally sign the JWS.
    public var jwk: String? {
        set {
            parameters["jwk"] = newValue
        }
        get {
            return parameters["jwk"] as? String
        }
    }

    /// The Key ID indicates the key which was used to secure the JWS.
    public var kid: String? {
        set {
            parameters["kid"] = newValue
        }
        get {
            return parameters["kid"] as? String
        }
    }

    /// The X.509 URL that referes to a resource for the X.509 public key certificate
    /// or certificate chain corresponding to the key used to sign the JWS.
    public var x5u: URL? {
        set {
            parameters["x5u"] = newValue?.absoluteString
        }
        get {
            guard let parameter = parameters["x5u"] as? String else {
                return nil
            }
            return URL(string: parameter)
        }
    }

    /// The X.509 certificate chain contains the X.509 public key certificate or
    /// certificate chain corresponding to the key used to sign the JWS.
    public var x5c: [String]? {
        set {
            parameters["x5c"] = newValue
        }
        get {
            return parameters["x5c"] as? [String]
        }
    }

    /// The X.509 certificate SHA-1 thumbprint of the DER encoding of the X.509 certificate
    /// corresponding to the key used to sign the JWS.
    public var x5t: String? {
        set {
            parameters["x5t"] = newValue
        }
        get {
            return parameters["x5t"] as? String
        }
    }

    /// The X.509 certificate SHA-256 thumbprint of the DER encoding of the X.509 certificate
    /// corresponding to the key used to sign the JWS.
    public var x5tS256: String? {
        set {
            parameters["x5tS256"] = newValue
        }
        get {
            return parameters["x5tS256"] as? String
        }
    }

    /// The type to declare the media type of the JWS object.
    public var typ: String? {
        set {
            parameters["typ"] = newValue
        }
        get {
            return parameters["typ"] as? String
        }
    }

    /// The content type to declare the media type of the secured content (payload).
    public var cty: String? {
        set {
            parameters["cty"] = newValue
        }
        get {
            return parameters["cty"] as? String
        }
    }

    /// The critical header parameter indicates the header parameter extensions.
    public var crit: [String]? {
        set {
            parameters["crit"] = newValue
        }
        get {
            return parameters["crit"] as? [String]
        }
    }
}
