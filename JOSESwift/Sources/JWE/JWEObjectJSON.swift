//
//  JWEObjectJSON.swift
//  JOSESwift
//
//  Created by Prem Eide on 02/12/2025.
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

internal enum JWEObjectJSONError: Error {
    case invalidJSON
    case missingField(String)
    case noRecipients
    case recipientNotFound
    case missingKeyManagementAlgorithm
    case missingContentEncryptionAlgorithm
    case couldNotConstructDecrypter
}

/// A JWE secured object using the general or flattened JSON serialization.
///
/// Unlike the compact serialization (`JWE`) it can carry multiple recipients, each with
/// its own key management algorithm and encrypted key. Decrypt it with `decrypt(using:)`.
///
/// See [RFC 7516, Section 7.2](https://www.rfc-editor.org/rfc/rfc7516#section-7.2).
public struct JWEObjectJSON {
    /// The integrity-protected, shared header.
    public let header: JWEHeader

    /// The list of recipients. The flattened serialization is represented as a
    /// single recipient with no per-recipient header.
    public let recipients: [Recipient]

    /// The initialization vector.
    public let initializationVector: Base64URL

    /// The ciphertext.
    public let ciphertext: Base64URL

    /// The authentication tag.
    public let authenticationTag: Base64URL

    /// The optional top-level `aad` member, if present.
    private let aad: Base64URL?

    /// The encrypted content encryption key: `nil` with no recipients, the single
    /// recipient's key, or the base64url `{"recipients": [...]}` object for multiple
    /// recipients (resolved by `MultiDecryptor`).
    public var encryptedKey: Base64URL? {
        if recipients.isEmpty {
            return nil
        }
        if recipients.count == 1 {
            return recipients[0].encryptedKey
        }
        let recipientsObject = ["recipients": recipients.map { $0.toJSONObject() }]
        guard let data = try? JSONSerialization.data(withJSONObject: recipientsObject) else {
            return nil
        }
        return Base64URL(data)
    }

    /// The additional authenticated data: `ASCII(BASE64URL(protected header))`, plus
    /// `'.' || aad` when the optional top-level `aad` member is present (RFC 7516 §5.1).
    public var additionalAuthenticatedData: Data {
        var data = header.data().base64URLEncodedData()
        if let aad = aad {
            data.append(Data(".\(aad.value)".utf8))
        }
        return data
    }

    /// Parses a `JWEObjectJSON` from its JSON serialization string.
    public init(jsonString: String) throws {
        try self.init(json: Data(jsonString.utf8))
    }

    /// Parses a `JWEObjectJSON` from its JSON serialization data.
    public init(json: Data) throws {
        let raw = try Self.parseJSONObject(json)

        self.header = try Self.parseProtectedHeader(Self.getBase64URL(forKey: "protected", in: raw))
        self.ciphertext = try Self.getBase64URL(forKey: "ciphertext", in: raw)
        self.initializationVector = try Self.getBase64URL(forKey: "iv", in: raw)
        self.authenticationTag = try Self.getBase64URL(forKey: "tag", in: raw)
        self.recipients = try Self.parseRecipients(from: raw)
        self.aad = (raw["aad"] as? String).map(Base64URL.init)
    }

    /// Decrypts the JWE with the given decrypter and returns the payload.
    public func decrypt(using decrypter: JWEDecrypter) throws -> Payload {
        guard let encryptedKey = encryptedKey else {
            throw JWEObjectJSONError.noRecipients
        }

        let decryptedData = try decrypter.decrypt(
            header: header,
            encryptedKey: encryptedKey,
            initializationVector: initializationVector,
            ciphertext: ciphertext,
            authenticationTag: authenticationTag,
            additionalAuthenticatedData: additionalAuthenticatedData
        )

        return Payload(decryptedData)
    }
}

extension JWEObjectJSON {
    static func parseJSONObject(_ jsonData: Data) throws -> [String: Any] {
        guard let raw = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            throw JWEObjectJSONError.invalidJSON
        }
        return raw
    }

    static func getBase64URL(forKey key: String, in raw: [String: Any]) throws -> Base64URL {
        guard let string = raw[key] as? String else {
            throw JWEObjectJSONError.missingField(key)
        }
        return Base64URL(string)
    }

    static func parseProtectedHeader(_ protected: Base64URL) throws -> JWEHeader {
        let headerData = try protected.decode()
        guard let parameters = try JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            throw JWEObjectJSONError.invalidJSON
        }
        return try JWEHeader(parameters: parameters, headerData: headerData)
    }

    static func parseRecipients(from raw: [String: Any]) throws -> [Recipient] {
        if let recipientsArray = raw["recipients"] as? [[String: Any]] {
            // General serialization.
            return try recipientsArray.map(Recipient.parse)
        }
        // Flattened serialization.
        let encryptedKey = try getBase64URL(forKey: "encrypted_key", in: raw)
        return [Recipient(unprotectedHeader: nil, encryptedKey: encryptedKey)]
    }
}
