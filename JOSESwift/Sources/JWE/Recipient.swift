//
//  Recipient.swift
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

/// A single recipient of a JWE in JSON serialization.
///
/// See [RFC 7516, Section 7.2.1](https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1).
public struct Recipient {
    /// The per-recipient unprotected header. `nil` for the flattened serialization,
    /// where the key management algorithm is in the shared protected header.
    public let unprotectedHeader: UnprotectedHeader?

    /// The recipient's encrypted content encryption key.
    public let encryptedKey: Base64URL

    public init(unprotectedHeader: UnprotectedHeader?, encryptedKey: Base64URL) {
        self.unprotectedHeader = unprotectedHeader
        self.encryptedKey = encryptedKey
    }

    /// The recipient as a JSON object matching the JWE JSON serialization.
    public func toJSONObject() -> [String: Any] {
        var json: [String: Any] = ["encrypted_key": encryptedKey.value]
        if let unprotectedHeader = unprotectedHeader {
            json["header"] = unprotectedHeader.toJSONObject()
        }
        return json
    }

    /// Parses a `Recipient` from a JSON object.
    public static func parse(_ json: [String: Any]) throws -> Recipient {
        let unprotectedHeader = (json["header"] as? [String: Any]).map(UnprotectedHeader.parse)
        let encryptedKey = try JWEObjectJSON.getBase64URL(forKey: "encrypted_key", in: json)
        return Recipient(unprotectedHeader: unprotectedHeader, encryptedKey: encryptedKey)
    }
}
