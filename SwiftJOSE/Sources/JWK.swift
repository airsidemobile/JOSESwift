//
//  JWK.swift
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

/// The key type parameter of a JWK identifies the cryptographic algorithm
/// family used with the key(s) represented by a JWK.
/// See [RFC-7518](https://tools.ietf.org/html/rfc7518#section-7.4) for details.
///
/// - RSA
public enum JWKKeyType: String, Codable {
    case RSA = "RSA"
}

/// A JWK object that represents a key or a key pair of a certain type.
/// Check `KeyType` for the supported key types.
public protocol JWK: Encodable {
    /// The cryptographic algorithm family used with the JWK.
    var keyType: JWKKeyType { get }

    /// The parameters of the JWK representing the properties of the key(s), including the value(s).
    /// Check [RFC 7517, Section 4](https://tools.ietf.org/html/rfc7517#section-4) and
    /// [RFC 7518, Section 6](https://tools.ietf.org/html/rfc7518#section-6) for possible parameters.
    var parameters: [String: String] { get }

    /// Accesses the specified parameter.
    /// The parameters of the JWK representing the properties of the key(s), including the value(s).
    /// Check [RFC 7517, Section 4](https://tools.ietf.org/html/rfc7517#section-4) and
    /// [RFC 7518, Section 6](https://tools.ietf.org/html/rfc7518#section-6) for possible parameters.
    ///
    /// - Parameter parameter: The desired parameter.
    subscript(parameter: String) -> String? { get }

    /// Computes the JSON representation of the JWK.
    ///
    /// - Returns: The JSON representation of the JWK as `String` or
    ///            `nil` if the encoding failed.
    func jsonString() -> String?

    /// Computes the JSON representation of the JWK.
    ///
    /// - Returns: The JSON representation of the JWK as `Data` or
    ///            `nil` if the encoding failed.
    func jsonData() -> Data?
}
