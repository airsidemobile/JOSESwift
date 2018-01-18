//
//  JWKParser.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 11.01.18.
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

/// Convenience class for parsing JWKs from `Data`, `String`, or `[String: Any] dictionaries.
public class JWKParser {

    /// Constructs a `JWK` from a given dictionary.
    ///
    /// - Parameter parameters: The `JWK` parameters dictionary.
    /// - Returns: A fully initialized `JWK`.
    /// - Throws: `JWKError` if any errors occur while parsing the provided parameters.
    public func parse(_ parameters: [String: Any]) throws -> JWK {
        guard
            let rawValue = parameters[JWKKeyType.parameterName] as? String,
            let keyType = JWKKeyType(rawValue: rawValue)
        else {
            throw JWKError.RequiredJWKParameterMissing(parameter: JWKKeyType.parameterName)
        }

        switch keyType {
        case .RSA:
            return try parseRSA(from: parameters)
        }
    }

    /// Constructs a `JWK` from a given `Data` object.
    ///
    /// - Parameter parameters: The `Data` to construct a `JWK` from.
    /// - Returns: A fully initialized `JWK`.
    /// - Throws: `JWKError` if any errors occur while parsing the provided data.
    public func parse(_ data: Data) throws -> JWK {
        guard
            let json = try? JSONSerialization.jsonObject(with: data, options: []),
            let parameters = json as? [String: Any]
        else {
            throw JWKError.JWKDataNotInTheRightFormat
        }

        return try parse(parameters)
    }

    /// Constructs a `JWK` from a given `String`.
    ///
    /// - Parameter parameters: The `String` to construct a `JWK` from.
    /// - Returns: A fully initialized `JWK`.
    /// - Throws: `JWKError` if any errors occur while parsing the provided string.
    public func parse(_ string: String) throws -> JWK {
        guard let data = string.data(using: .utf8) else {
            throw JWKError.JWKStringNotInTheRightFormat
        }

        return try parse(data)
    }
}
