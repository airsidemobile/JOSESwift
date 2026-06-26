//
//  UnprotectedHeader.swift
//  JOSESwift
//
//  Created by Prem Eide on 12/12/2025.
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

/// An unprotected (not integrity-protected) JOSE header used by the JWE JSON
/// serialization, either shared or per-recipient.
///
/// See [RFC 7516, Section 7.2](https://www.rfc-editor.org/rfc/rfc7516#section-7.2).
public struct UnprotectedHeader {
    /// The raw header parameters.
    public let parameters: [String: Any]

    public init(parameters: [String: Any]) {
        self.parameters = parameters
    }

    /// The key ID (`kid`) used to identify the recipient's key, if present.
    public var keyID: String? {
        param("kid") as? String
    }

    /// Returns the value of the specified header parameter, or `nil` if absent.
    public func param(_ name: String) -> Any? {
        parameters[name]
    }

    /// The names of the parameters included in this header.
    public var includedParams: Set<String> {
        Set(parameters.keys)
    }

    /// The header as a JSON object.
    public func toJSONObject() -> [String: Any] {
        parameters
    }

    /// Parses an `UnprotectedHeader` from a JSON object.
    public static func parse(_ json: [String: Any]) -> UnprotectedHeader {
        UnprotectedHeader(parameters: json)
    }
}
