//
//  Base64URL.swift
//  JOSESwift
//
//  Created by Prem Eide on 10/12/2025.
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

internal enum Base64URLError: Error {
    case invalidBase64URLString
}

/// A type-safe wrapper around a base64url-encoded string, used by the JSON
/// serialization types to carry encoded values (ciphertext, IV, tag, encrypted keys).
public struct Base64URL {
    /// The base64url-encoded string value.
    public let value: String

    /// Creates a `Base64URL` from an already base64url-encoded string.
    public init(_ base64URL: String) {
        self.value = base64URL
    }

    /// Creates a `Base64URL` by base64url-encoding the given raw data.
    public init(_ data: Data) {
        self.value = data.base64URLEncodedString()
    }

    /// Decodes the wrapped value into its raw data representation.
    public func decode() throws -> Data {
        guard let data = Data(base64URLEncoded: value) else {
            throw Base64URLError.invalidBase64URLString
        }
        return data
    }
}
