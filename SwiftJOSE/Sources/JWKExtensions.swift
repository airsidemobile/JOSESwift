//
//  JWKExtensions.swift
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

// MARK: Subscript

public extension JWK {
    subscript(parameter: String) -> Any? {
        return parameters[parameter]
    }
}

// MARK: JSON

public extension JWK {
    func jsonString() throws -> String {
        guard JSONSerialization.isValidJSONObject(parameters) else {
            throw JWKError.JWKToJSONConversionFailed
        }

        // The forced unwrap is ok here since we checked `isValidJSONObject` above.
        // swiftlint:disable:next force_try
        let jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])

        // The forced unwrap is ok here since `JSONSerialization.data()` returns UTF-8.
        // swiftlint:disable:next force_unwrap
        return String(data: jsonData, encoding: .utf8)!
    }

    func jsonData() throws -> Data {
        guard JSONSerialization.isValidJSONObject(parameters) else {
            throw JWKError.JWKToJSONConversionFailed
        }

        // The forced unwrap is ok here since we checked `isValidJSONObject` above.
        // swiftlint:disable:next force_try
        let jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])

        return jsonData
    }
}

// MARK: Parsing

extension JWK {
    public static func parse(_ parameters: [String: Any]) throws -> JWK {
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

    public static func parse(_ data: Data) throws -> JWK {
        guard
            let json = try? JSONSerialization.jsonObject(with: data, options: []),
            let parameters = json as? [String: Any]
        else {
            throw JWKError.JWKDataNotInTheRightFormat
        }

        return try parse(parameters)
    }

    public static func parse(_ string: String) throws -> JWK {
        guard let data = string.data(using: .utf8) else {
            throw JWKError.JWKStringNotInTheRightFormat
        }

        return try parse(data)
    }
}
