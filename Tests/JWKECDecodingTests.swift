// swiftlint:disable force_unwrapping
//
//  JWKECDecodingTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 09.01.2019.
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

class JWKECDecodingTests: ECCryptoTestCase {

    private struct Consts {
        static let keyX = "TvQ0_muDyvS4RX9bJm8Rzy9XTpSG7xwo3Ffgu8Oq7OY"
        static let keyY = "saNr4hM3qrojSoY4eaO1WGVna5yW_I4EqdFQ4TRl8iQ"
        static let keyD = "EupBKRVOSC4BkqUoiXCtVoIZv8glXvIDDkwdz0aKfiU"
        static let kid = "2018-TEST"

        static let innerKeyJSONKeyType = "\"kty\":\"EC\""
        static let innerKeyJSONWrongKeyType = "\"kty\":\"RSA\""
        static let innerKeyJSONX = "\"x\":\"\(keyX)\""
        static let innerKeyJSONY = "\"y\":\"\(keyY)\""
        static let innerKeyJSOND = "\"d\":\"\(keyD)\""
        static let innerKeyJSON = "\"crv\":\"\(ECCurveType.P256.rawValue)\",\"kid\":\"\(kid)\""

        static let publicKeyJSON = """
                            {\
                            \(innerKeyJSONKeyType),\
                            \(innerKeyJSON),\
                            \(innerKeyJSONX),\
                            \(innerKeyJSONY),\
                            }
                            """.data(using: .utf8)!

        static let privateKeyJSON = """
                             {\
                             \(innerKeyJSONKeyType),\
                             \(innerKeyJSON),\
                             \(innerKeyJSONX),\
                             \(innerKeyJSONY),\
                             \(innerKeyJSOND)\
                             }
                             """.data(using: .utf8)!

    }

    // MARK: - Public Key Tests

    func testInitializingPublicKeyFromJSONData() {
        let jwk = try? ECPublicKey(data: Consts.publicKeyJSON)

        XCTAssertNotNil(jwk)
        checkSharedKeyComponents(jwk: jwk!)
    }

    func testDecodingPublicKey() {
        let jwk = try? JSONDecoder().decode(ECPublicKey.self, from: Consts.publicKeyJSON)

        XCTAssertNotNil(jwk)
        checkSharedKeyComponents(jwk: jwk!)
    }

    func testDecodingPublicKeyMissingKeyType() {
        let publicKeyJSONMissingKeyType = encloseJson([
            Consts.innerKeyJSON,
            Consts.innerKeyJSONX,
            Consts.innerKeyJSONY
        ])
        checkMissingKey(json: publicKeyJSONMissingKeyType, key: JWKParameter.keyType.rawValue)
    }

    func testDecodingPublicKeyWrongKeyType() {
        let publicKeyJSONWrongKeyType = encloseJson([
            Consts.innerKeyJSONWrongKeyType,
            Consts.innerKeyJSON,
            Consts.innerKeyJSONX,
            Consts.innerKeyJSONY
        ])
        checkMissingKey(json: publicKeyJSONWrongKeyType, key: JWKParameter.keyType.rawValue)
    }

    func testDecodingPublicKeyMissingX() {
        let publicKeyJSONMissingX = encloseJson([
            Consts.innerKeyJSONKeyType,
            Consts.innerKeyJSON,
            Consts.innerKeyJSONY
        ])
        checkMissingKey(json: publicKeyJSONMissingX, key: ECParameter.x.rawValue)
    }

    func testDecodingPublicKeyMissingY() {
        let publicKeyJSONMissingY = encloseJson([
            Consts.innerKeyJSONKeyType,
            Consts.innerKeyJSON,
            Consts.innerKeyJSONX
        ])
        checkMissingKey(json: publicKeyJSONMissingY, key: ECParameter.y.rawValue)
    }

    func testDecodingPublicKeyWrongDataFormat() {
        let wrongPublicKey = "{\"kty\":\"EC\"".data(using: .utf8)!

        do {
            _ = try JSONDecoder().decode(ECPublicKey.self, from: wrongPublicKey)
        } catch DecodingError.dataCorrupted(let context) {
            XCTAssertEqual(context.debugDescription, "The given data was not valid JSON.")
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    // MARK: - Private Key Tests

    func testInitializingPrivateKeyFromJSONData() {
        let jwk = try? ECPrivateKey(data: Consts.privateKeyJSON)

        XCTAssertNotNil(jwk)
        checkSharedKeyComponents(jwk: jwk!)
        XCTAssertEqual(jwk?.privateKey, Consts.keyD)
    }

    func testDecodingPrivateKey() {
        let jwk = try? JSONDecoder().decode(ECPrivateKey.self, from: Consts.privateKeyJSON)

        XCTAssertNotNil(jwk)
        checkSharedKeyComponents(jwk: jwk!)
        XCTAssertEqual(jwk?.privateKey, Consts.keyD)
    }

    func testDecodingPrivateKeyMissingKeyType() {
        let privateKeyJSONMissingKeyType = encloseJson([
            Consts.innerKeyJSON,
            Consts.innerKeyJSONX,
            Consts.innerKeyJSONY,
            Consts.innerKeyJSOND
        ])
        checkMissingKeyPrivate(json: privateKeyJSONMissingKeyType, key: JWKParameter.keyType.rawValue)
    }

    func testDecodingPrivateKeyWrongKeyType() {
        let privateKeyJSONWrongKeyType = encloseJson([
            Consts.innerKeyJSONWrongKeyType,
            Consts.innerKeyJSON,
            Consts.innerKeyJSONX,
            Consts.innerKeyJSONY,
            Consts.innerKeyJSOND
        ])
        checkMissingKeyPrivate(json: privateKeyJSONWrongKeyType, key: JWKParameter.keyType.rawValue)
    }

    func testDecodingPrivateKeyMissingX() {
        let privateKeyJSONMissingX = encloseJson([
            Consts.innerKeyJSONKeyType,
            Consts.innerKeyJSON,
            Consts.innerKeyJSONY,
            Consts.innerKeyJSOND
        ])
        checkMissingKeyPrivate(json: privateKeyJSONMissingX, key: ECParameter.x.rawValue)
    }

    func testDecodingPrivateKeyMissingExponent() {
        let privateKeyJSONMissingY = encloseJson([
            Consts.innerKeyJSONKeyType,
            Consts.innerKeyJSON,
            Consts.innerKeyJSONX,
            Consts.innerKeyJSOND
        ])
        checkMissingKeyPrivate(json: privateKeyJSONMissingY, key: ECParameter.y.rawValue)
    }

    func testDecodingPrivateKeyMissingPrivateKey() {
        let privateKeyJSONMissingPrivateKey = encloseJson([
            Consts.innerKeyJSONKeyType,
            Consts.innerKeyJSON,
            Consts.innerKeyJSONX,
            Consts.innerKeyJSONY
        ])
        checkMissingKeyPrivate(json: privateKeyJSONMissingPrivateKey, key: ECParameter.privateKey.rawValue)
    }

    func testDecodingPrivateKeyWrongDataFormat() {
        let wrongPrivateKey = "{\"kty\":\"EC\"".data(using: .utf8)!

        do {
            _ = try JSONDecoder().decode(ECPrivateKey.self, from: wrongPrivateKey)
        } catch DecodingError.dataCorrupted(let context) {
            XCTAssertEqual(context.debugDescription, "The given data was not valid JSON.")
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testBuildingJWKSetShouldNotFailIfCertificatesOrKeyOpsArePresent() {
        let jwkSet = """
        {
            "keys": [{
                \(Consts.innerKeyJSONKeyType),
                \(Consts.innerKeyJSONX),
                \(Consts.innerKeyJSONY),
                \(Consts.innerKeyJSOND),
                \(Consts.innerKeyJSON),
                "x5c": ["Y2VydGlmaWNhdGUxMjM0NWRhdGEx"]
            }, {
                \(Consts.innerKeyJSONKeyType),
                \(Consts.innerKeyJSONX),
                \(Consts.innerKeyJSONY),
                \(Consts.innerKeyJSON),
                "key_ops": ["sign", "encrypt"]
            }]
        }
        """.data(using: .utf8)!

        XCTAssertNoThrow(try JWKSet(data: jwkSet))
    }

    // MARK: Helper functions

    private func encloseJson(_ elements: [String]) -> Data {
        let inner = elements.joined(separator: ",")
        return "{\(inner)}".data(using: .utf8)!
    }

    private func checkSharedKeyComponents(jwk: ECPublicKey) {
        XCTAssertEqual(jwk.keyType, .EC)
        XCTAssertEqual(jwk["kty"] ?? "", "EC")
        XCTAssertEqual(jwk.x, Consts.keyX)
        XCTAssertEqual(jwk.y, Consts.keyY)
        XCTAssertEqual(jwk.crv, ECCurveType.P256)
        XCTAssertEqual(jwk["kid"] ?? "", Consts.kid)
    }

    private func checkSharedKeyComponents(jwk: ECPrivateKey) {
        XCTAssertEqual(jwk.keyType, .EC)
        XCTAssertEqual(jwk["kty"] ?? "", "EC")
        XCTAssertEqual(jwk.x, Consts.keyX)
        XCTAssertEqual(jwk.y, Consts.keyY)
        XCTAssertEqual(jwk.crv, ECCurveType.P256)
        XCTAssertEqual(jwk["kid"] ?? "", Consts.kid)
    }

    private func checkMissingKey(json: Data, key: String) {
        do {
            _ = try JSONDecoder().decode(ECPublicKey.self, from: json)
        } catch DecodingError.keyNotFound(let k, _) {
            XCTAssertEqual(k.stringValue, key)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    private func checkMissingKeyPrivate(json: Data, key: String) {
        do {
            _ = try JSONDecoder().decode(ECPrivateKey.self, from: json)
        } catch DecodingError.keyNotFound(let k, _) {
            XCTAssertEqual(k.stringValue, key)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

}
// swiftlint:enable force_unwrapping
