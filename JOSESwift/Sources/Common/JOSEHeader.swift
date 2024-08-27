//
//  JOSEHeader.swift
//  JOSESwift
//
//  Created by Daniel Egger on 20/09/2017.
//
//  ---------------------------------------------------------------------------
//  Copyright 2024 Airside Mobile Inc.
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

enum HeaderParsingError: Error {
    case requiredHeaderParameterMissing(parameter: String)
    case headerIsNotValidJSONObject
}

/// A `JOSEHeader` is a JSON object representing various Header Parameters.
/// Moreover, a `JOSEHeader` is a `JOSEObjectComponent`. Therefore it can be initialized from and converted to `Data`.
protocol JOSEHeader: DataConvertible, CommonHeaderParameterSpace {
    var headerData: Data { get }
    var parameters: [String: Any] { get set }

    var requiredParameters: [String] { get }

    init(parameters: [String: Any], headerData: Data) throws

    init?(_ data: Data)
    func data() -> Data
}

extension JOSEHeader {
    public mutating func set(_ value: Any, forParameter parameterName: String) throws {
        guard !requiredParameters.contains(parameterName) else {
            throw JOSESwiftError.invalidHeaderParameterValue
        }

        guard JSONSerialization.isValidJSONObject([parameterName: value]) else {
            throw JOSESwiftError.invalidHeaderParameterValue
        }

        parameters[parameterName] = value
    }

    public func get(parameter parameterName: String) -> Any? {
        return parameters[parameterName]
    }

    @discardableResult public mutating func remove(parameter parameterName: String) -> Any? {
        guard !requiredParameters.contains(parameterName) else {
            return nil
        }

        return parameters.removeValue(forKey: parameterName)
    }
}

// `DataConvertible` implementation.
extension JOSEHeader {
    public init?(_ data: Data) {
        // Verify that the header is a completely valid JSON object.
        guard
            let json = try? JSONSerialization.jsonObject(with: data, options: []),
            let parameters = json as? [String: Any]
        else {
            return nil
        }

        try? self.init(parameters: parameters, headerData: data)
    }

    public func data() -> Data {
        return headerData
    }
}

/// JWS and JWE share a common Header Parameter space that both JWS and JWE headers must support.
/// Those header parameters may have a different meaning depending on whether they are part of a JWE or JWS.
public protocol CommonHeaderParameterSpace {
    var jku: URL? { get set }
    var jwk: String? { get set }
    var jwkTyped: JWK? { get set }
    var kid: String? { get set }
    var x5u: URL? { get set }
    var x5c: [String]? { get set }
    var x5t: String? { get set }
    var x5tS256: String? { get set }
    var typ: String? { get set }
    var cty: String? { get set }
    var crit: [String]? { get set }
}
