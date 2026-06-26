//
//  JWEDecrypter.swift
//  JOSESwift
//
//  Created by Prem Eide on 05/12/2025.
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

/// A type that can decrypt the parts of a JWE.
public protocol JWEDecrypter {
    /// Decrypts the given JWE parts and returns the plaintext.
    ///
    /// For a JSON serialization with multiple recipients, `encryptedKey` holds the
    /// base64url-encoded `{"recipients": [...]}` object that a `MultiDecryptor` uses to
    /// select the matching recipient.
    func decrypt(
        header: JWEHeader,
        encryptedKey: Base64URL,
        initializationVector: Base64URL,
        ciphertext: Base64URL,
        authenticationTag: Base64URL,
        additionalAuthenticatedData: Data
    ) throws -> Data
}
