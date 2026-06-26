//
//  JWEObjectJSONTests.swift
//  Tests
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

import XCTest
@testable import JOSESwift

final class JWEObjectJSONTests: XCTestCase {

    // A parse-only fixture mixing an RSA and an EC recipient (general serialization).
    private let generalJSONJWECombined = """
    {
        "ciphertext": "cBE1WhgQcg9iA1pcYe6hCO8XdqJ_ZGReEAOeqw9iJaHhQsMzvWlD_ErX5KOd5hI0wZvc",
        "protected": "eyJ0eXAiOiJKV0UiLCJlbmMiOiJBMjU2R0NNIn0",
        "recipients": [
            {
                "encrypted_key": "TnBh1cV3P8sbqnWoajeeuyBQf9oNiOp2hPxxprO6mLepq1zt0V-Jed2P5-ZAYpOq5JaPKn7egvfs0uuMsFAL4xt7EgSZfYHuXUHMZRNVATrmoXR70bXCH9__vMtSYBrceVWSJSwF01TaNGwPrwetu2hvGO7YVXF5wDjJKB-cnJ5M4U3em0cNoSM986VgyZG3ArztxmKiWs3TX8u03QkUNTG0lWjFHEvHwLt9tGJMoiwx4tfh5Q0OcuxcA1xFYeOy9JsP2LNe6rCKjgA396np5us22-coqABttwY8kA78wTsr4YEus8NyhogaCV6aJ-S-NnhNMISkUlnU-kmnX3WDZA",
                "header": {
                    "alg": "RSA-OAEP-256",
                    "kid": "rsa1"
                }
            },
            {
                "encrypted_key": "fDP0iySx6SnQao0xegMesiNq3v5GrVgTax5sh3Y6TMV5LX1YMXRLhg",
                "header": {
                    "epk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "x7b6-aldF4veusN1YlK1kHv1m8xUp2BxPG3rcrMyY2U",
                        "y": "CESJcKwPhK4Il8hAVSNke8wq6SbHqY_BCWuIkntk5Bk"
                    },
                    "alg": "ECDH-ES+A256KW",
                    "kid": "ec1"
                }
            }
        ],
        "tag": "bUky-v6rh_Ge7_CFMQOTuw",
        "iv": "GdKaxFnxvcWweY-X"
    }
    """

    // MARK: - Parsing

    func testParsingGeneralJSONJWE() throws {
        let jwe = try JWEObjectJSON(jsonString: generalJSONJWECombined)

        XCTAssertEqual(jwe.recipients.count, 2)
        XCTAssertEqual(jwe.ciphertext.value, "cBE1WhgQcg9iA1pcYe6hCO8XdqJ_ZGReEAOeqw9iJaHhQsMzvWlD_ErX5KOd5hI0wZvc")
        XCTAssertEqual(jwe.initializationVector.value, "GdKaxFnxvcWweY-X")
        XCTAssertEqual(jwe.authenticationTag.value, "bUky-v6rh_Ge7_CFMQOTuw")

        XCTAssertEqual(jwe.header.parameters["enc"] as? String, "A256GCM")

        XCTAssertEqual(jwe.recipients[0].unprotectedHeader?.param("alg") as? String, "RSA-OAEP-256")
        XCTAssertEqual(jwe.recipients[0].unprotectedHeader?.keyID, "rsa1")
        XCTAssertEqual(jwe.recipients[1].unprotectedHeader?.param("alg") as? String, "ECDH-ES+A256KW")
        XCTAssertEqual(jwe.recipients[1].unprotectedHeader?.keyID, "ec1")
    }

    func testParsingFlattenedJSONJWE() throws {
        let flattened = """
        {
            "protected": "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0",
            "encrypted_key": "fDP0iySx6SnQao0xegMesiNq3v5GrVgTax5sh3Y6TMV5LX1YMXRLhg",
            "iv": "GdKaxFnxvcWweY-X",
            "ciphertext": "OiouIje2Yrec1J9Whw",
            "tag": "bUky-v6rh_Ge7_CFMQOTuw"
        }
        """

        let jwe = try JWEObjectJSON(jsonString: flattened)

        XCTAssertEqual(jwe.recipients.count, 1)
        XCTAssertNil(jwe.recipients[0].unprotectedHeader)
        XCTAssertEqual(jwe.recipients[0].encryptedKey.value, "fDP0iySx6SnQao0xegMesiNq3v5GrVgTax5sh3Y6TMV5LX1YMXRLhg")
        XCTAssertEqual(jwe.header.keyManagementAlgorithm, .RSAOAEP256)
        XCTAssertEqual(jwe.header.contentEncryptionAlgorithm, .A256GCM)
    }

    func testParsingMissingFieldThrows() {
        let missingCiphertext = """
        { "protected": "eyJlbmMiOiJBMjU2R0NNIn0", "iv": "GdKaxFnxvcWweY-X", "tag": "bUky-v6rh_Ge7_CFMQOTuw", "encrypted_key": "AA" }
        """
        XCTAssertThrowsError(try JWEObjectJSON(jsonString: missingCiphertext))
    }

    // MARK: - Header merging

    func testMergingProtectedAndUnprotectedHeaders() throws {
        let jwe = try JWEObjectJSON(jsonString: generalJSONJWECombined)

        let recipientHeader = try XCTUnwrap(jwe.recipients[0].unprotectedHeader)
        let merged = try jwe.header.join(recipientHeader)

        XCTAssertEqual(merged.parameters["enc"] as? String, "A256GCM")
        XCTAssertEqual(merged.parameters["alg"] as? String, "RSA-OAEP-256")
        XCTAssertEqual(merged.parameters["kid"] as? String, "rsa1")
    }

    func testMergingCollidingHeadersThrows() throws {
        let jwe = try JWEObjectJSON(jsonString: generalJSONJWECombined)

        let collidingHeader = UnprotectedHeader(parameters: ["enc": "A128GCM"])

        XCTAssertThrowsError(try jwe.header.join(collidingHeader)) { error in
            guard case JWEError.nonDisjointHeaders = error else {
                return XCTFail("Expected nonDisjointHeaders, got \(error)")
            }
        }
    }

    // MARK: - Decryption

    /// Builds a flattened JWE JSON from JOSESwift's own compact serialization and
    /// verifies it decrypts back to the original payload. This exercises the full
    /// decryption path, including the AAD computed from the raw protected header.
    func testDecryptFlattenedRoundtrip() throws {
        let publicKey = try ECPublicKey(data: Self.ecPublicJWK)
        let privateKey = try ECPrivateKey(data: Self.ecPrivateJWK)

        let input = Data("Live long and prosper.".utf8)
        let encrypter = try XCTUnwrap(Encrypter(
            keyManagementAlgorithm: .ECDH_ES_A128KW,
            contentEncryptionAlgorithm: .A256CBCHS512,
            encryptionKey: publicKey
        ))
        let jwe = try JWE(
            header: JWEHeader(keyManagementAlgorithm: .ECDH_ES_A128KW, contentEncryptionAlgorithm: .A256CBCHS512),
            payload: Payload(input),
            encrypter: encrypter
        )

        let parts = jwe.compactSerializedString.components(separatedBy: ".")
        XCTAssertEqual(parts.count, 5)
        let flattened = """
        {"protected":"\(parts[0])","encrypted_key":"\(parts[1])","iv":"\(parts[2])","ciphertext":"\(parts[3])","tag":"\(parts[4])"}
        """

        let object = try JWEObjectJSON(jsonString: flattened)
        let decrypted = try object.decrypt(using: MultiDecryptor(jwk: privateKey))

        XCTAssertEqual(decrypted.data(), input)
    }

    /// Decrypts a multi-recipient (general serialization) JWE produced by an
    /// independent JOSE implementation, selecting the correct recipient by key.
    func testDecryptMultiRecipientSelectsCorrectRecipient() throws {
        let firstKey = try ECPrivateKey(data: Self.multiRecipientFirstPrivateJWK)
        let secondKey = try ECPrivateKey(data: Self.multiRecipientSecondPrivateJWK)
        let expected = Data("Live long and prosper.".utf8)

        let jwe = try JWEObjectJSON(jsonString: Self.multiRecipientJSON)

        XCTAssertEqual(jwe.recipients.count, 2)
        XCTAssertEqual(try jwe.decrypt(using: MultiDecryptor(jwk: firstKey)).data(), expected)
        XCTAssertEqual(try jwe.decrypt(using: MultiDecryptor(jwk: secondKey)).data(), expected)
    }

    func testDecryptWithUnknownKeyThrowsRecipientNotFound() throws {
        let unrelatedKey = try ECPrivateKey(data: Self.ecPrivateJWK)
        let jwe = try JWEObjectJSON(jsonString: Self.multiRecipientJSON)

        XCTAssertThrowsError(try jwe.decrypt(using: MultiDecryptor(jwk: unrelatedKey))) { error in
            guard case JWEObjectJSONError.recipientNotFound = error else {
                return XCTFail("Expected recipientNotFound, got \(error)")
            }
        }
    }
}

// MARK: - Fixtures

extension JWEObjectJSONTests {
    // A standalone EC key pair (P-256) used for the flattened round-trip.
    static let ecPublicJWK = Data("""
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "CQJxA68WhgU3hztigbedfLtJitDhScq3XSnXgO0FV5o",
        "y": "WFg6s36izURa733WqeoJ8zXMd7ho5OSwdWnMsEPgTEI"
    }
    """.utf8)

    static let ecPrivateJWK = Data("""
    {
        "kty": "EC",
        "crv": "P-256",
        "d": "920OCD0fW97YXbQNN-JaOtaDgbuNyVxXgKwjfXPPqv4",
        "x": "CQJxA68WhgU3hztigbedfLtJitDhScq3XSnXgO0FV5o",
        "y": "WFg6s36izURa733WqeoJ8zXMd7ho5OSwdWnMsEPgTEI"
    }
    """.utf8)

    // Generated with the `jose` library (ECDH-ES+A128KW, A256CBC-HS512, two recipients).
    static let multiRecipientJSON = """
    {
        "ciphertext": "Qb6h20OiMfbTJ0C0pcBBMQ2M0wkhHI4x7mQLbOSSE2Q",
        "iv": "6kZzZA6o9XVu7A8XveTHdQ",
        "recipients": [
            {
                "encrypted_key": "dkuYWUoYa04fIQlnxyHlTrfhDEjG7gixqB5-ENfNAGiI9ZxWPpEZwfGbdBRc9WbNUlKkjYCfIv7QrLMdmR5ILoN-9XB5-A-v",
                "header": {
                    "alg": "ECDH-ES+A128KW",
                    "kid": "y3SJVWelgRjWPzwdvk11tlCQw-yP-1pfvapSZ6ifrSM",
                    "epk": {
                        "x": "o1AvLAuJV-BsLkwGS2UmcmZP1CYO3VWOJI2lckkfcWk",
                        "crv": "P-256",
                        "kty": "EC",
                        "y": "UfkRIQJZIKePNheXgGG2RNP6yBZvpy8LcXeVJcn93u8"
                    }
                }
            },
            {
                "encrypted_key": "Pdi13XNtT3dFOMcAFEjS90b3pPeg004uOrD5dGv7UVBfg8uQpmgPqDzWFy4ZYNZJVdTGz6kcewg6iLW02czKMLJWOtNwUkTp",
                "header": {
                    "alg": "ECDH-ES+A128KW",
                    "kid": "6b96cl2UvJks4KAwPD8Q3Q_v89rbeq9zuViza4qTlNk",
                    "epk": {
                        "x": "Csc-WBMxwQ5aLNCH29rAuWs_-5fsw_HeyOs9_12Vs30",
                        "crv": "P-256",
                        "kty": "EC",
                        "y": "yghVdRY5TqY7JxzszfZ2qgdWNcue3NFu3pLTP23571k"
                    }
                }
            }
        ],
        "tag": "HmMZhPZEE4MLQnf0zlYw9GeZUgwb5C1TC1IMLtTxtDQ",
        "protected": "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0"
    }
    """

    static let multiRecipientFirstPrivateJWK = Data("""
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "3IjA1VWlYlBP6HqgU8qvuNgln4q1KzY-0wTX7BDo-jk",
        "y": "pI2Ytekvgd9igFlcPBjMwYoBY-VyRDnO-v38KeriL3M",
        "d": "y2Pd9UQLv3vf1vuGmlEZKVBKsGPUDtce4GGfeiG4oz8",
        "kid": "y3SJVWelgRjWPzwdvk11tlCQw-yP-1pfvapSZ6ifrSM"
    }
    """.utf8)

    static let multiRecipientSecondPrivateJWK = Data("""
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "bSrXhiUEPNJrjp5uaYzBKkdS5YQoI5Qw0zKnUMgmDaQ",
        "y": "fgMZdvuZIsI1qVkSaRVpSt749f-ae1dQJs9quV6NL8k",
        "d": "Yin9KSLtTPRG8L3w6r91PTrLbmHActs7bC5r02bOGfo",
        "kid": "6b96cl2UvJks4KAwPD8Q3Q_v89rbeq9zuViza4qTlNk"
    }
    """.utf8)
}
