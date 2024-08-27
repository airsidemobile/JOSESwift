// swiftlint:disable force_unwrapping
//
//  SymmetricKeyTests.swift
//  Tests
//
//  Created by Daniel Egger on 10.07.18.
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

class SymmetricKeyTests: XCTestCase {

    func testCreatingSymmetricKeyFromData() {
        // Example key data from https://tools.ietf.org/html/rfc7517#appendix-A.3 but with different "alg" parameter
        // because we don't (yet) support "A128KW".
        let key = Data([
            0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5, 0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52
        ])

        let jwk = SymmetricKey(
            key: key,
            additionalParameters: [ "alg": ContentEncryptionAlgorithm.A256CBCHS512.rawValue ]
        )

        XCTAssertEqual(jwk.key, "GawgguFyGrWKav7AX4VKUg")
        XCTAssertEqual(jwk.keyType, .OCT)
        XCTAssertEqual(jwk["alg"], "A256CBC-HS512")

        XCTAssertEqual(
            "{\"alg\":\"A256CBC-HS512\",\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kty\":\"oct\"}",
            jwk.jsonString()!
        )
    }

    func testParsingSymmetricKeyFromJSONData() {
        let key = Data([
            0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5, 0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52
        ])

        let json = SymmetricKey(
            key: key,
            additionalParameters: [ "alg": ContentEncryptionAlgorithm.A256CBCHS512.rawValue ]
        ).jsonData()!

        let jwk = try! SymmetricKey(data: json)

        XCTAssertEqual(jwk.key, "GawgguFyGrWKav7AX4VKUg")
        XCTAssertEqual(jwk.keyType, .OCT)
        XCTAssertEqual(jwk["alg"], "A256CBC-HS512")

        XCTAssertEqual(
            "{\"alg\":\"A256CBC-HS512\",\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kty\":\"oct\"}",
            jwk.jsonString()!
        )
    }

    func testParsingSymmetricKeyFromOtherKeyRepresentation() {
        let key: ExpressibleAsSymmetricKeyComponents = Data([
            0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5, 0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52
        ])

        let json = try! SymmetricKey(
            key: key,
            additionalParameters: [ "alg": ContentEncryptionAlgorithm.A256CBCHS512.rawValue ]
        ).jsonData()!

        let jwk = try! SymmetricKey(data: json)

        XCTAssertEqual(jwk.key, "GawgguFyGrWKav7AX4VKUg")
        XCTAssertEqual(jwk.keyType, .OCT)
        XCTAssertEqual(jwk["alg"], "A256CBC-HS512")

        XCTAssertEqual(
            "{\"alg\":\"A256CBC-HS512\",\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kty\":\"oct\"}",
            jwk.jsonString()!
        )
    }

    func testSymmetricKeyToData() {
        let key = Data([
            0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5, 0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52
            ])

        let jwk = SymmetricKey(key: key)

        let keyData = try! jwk.converted(to: Data.self)

        XCTAssertEqual(keyData, key)
    }

    func testMalformedSymmetricKeyToData() {
        let json = "{\"kty\":\"oct\",\"alg\":\"A256CBC-HS512\",\"k\":\"+++==notbase64url==---\"}".data(using: .utf8)!

        XCTAssertThrowsError(try SymmetricKey(data: json))
    }

    func testDecodingFromJSONWithMissingKeyType() {
        let json = "{\"alg\":\"A256CBC-HS512\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}".data(using: .utf8)!

        XCTAssertThrowsError(try SymmetricKey(data: json))
    }

    func testDecodingFromJSONWithWrongKeyType() {
        let json = "{\"kty\":\"RSA\",\"alg\":\"A256CBC-HS512\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}".data(using: .utf8)!

        XCTAssertThrowsError(try SymmetricKey(data: json))
    }

    @available(iOS 11.0, *)
    func testThumbprintSymmetricKey() {
        let key = Data([
            0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5, 0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52
        ])

        let jwk = SymmetricKey(
            key: key,
            additionalParameters: [ JWKParameter.algorithm.rawValue: ContentEncryptionAlgorithm.A256CBCHS512.rawValue ]
        )

        XCTAssertEqual(try? jwk.thumbprint(), "k1JnWRfC-5zzmL72vXIuBgTLfVROXBakS4OmGcrMCoc")
    }

    @available(iOS 11.0, *)
    func testAddThumbprintToJWK() throws {
        let key = Data([
            0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5, 0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52
        ])

        let jwk = try SymmetricKey(
            key: key,
            additionalParameters: [ JWKParameter.algorithm.rawValue: ContentEncryptionAlgorithm.A256CBCHS512.rawValue ]
        ).withThumbprintAsKeyId()

        XCTAssertEqual(jwk.parameters[JWKParameter.keyIdentifier.rawValue], "k1JnWRfC-5zzmL72vXIuBgTLfVROXBakS4OmGcrMCoc")
    }

    @available(iOS 11.0, *)
    func testAddThumbprintToJWKCopyParameters() throws {
        let key = Data([
            0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5, 0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52
        ])

        let jwk = try SymmetricKey(
            key: key,
            additionalParameters: [ JWKParameter.algorithm.rawValue: ContentEncryptionAlgorithm.A256CBCHS512.rawValue ]
        ).withThumbprintAsKeyId()

        XCTAssertEqual(jwk.parameters[JWKParameter.keyIdentifier.rawValue], "k1JnWRfC-5zzmL72vXIuBgTLfVROXBakS4OmGcrMCoc")
        XCTAssertEqual(jwk.parameters[JWKParameter.algorithm.rawValue], ContentEncryptionAlgorithm.A256CBCHS512.rawValue)
    }
}
// swiftlint:enable force_unwrapping
