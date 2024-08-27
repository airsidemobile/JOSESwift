// swiftlint:disable force_unwrapping
//
//  JWKECKeysTests.swift
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

class JWKECKeysTests: ECCryptoTestCase {

    func testMergingDuplicateAdditionalParametersInPublicKey() {
        allTestData.forEach { keyData in
            let params = [ "kty": "wrongKty" ]
            let jwk = try! ECPublicKey(publicKey: keyData.publicKey, additionalParameters: params)

            XCTAssertEqual(jwk["kty"] ?? "", "EC")
        }
    }

    func testMergingDuplicateAdditionalParametersInPrivateKey() {
        allTestData.forEach { keyData in
            let jwk = try! ECPrivateKey(
                    crv: keyData.expectedCurveType,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url,
                    privateKey: keyData.expectedPrivateBase64Url,
                    additionalParameters: [ "kty": "wrongKty" ]
            )

            XCTAssertEqual(jwk["kty"] ?? "", "EC")
        }
    }

    func testInitPublicKeyDirectlyWithoutAdditionalParameters() {
        allTestData.forEach { keyData in
            let key = ECPublicKey(
                    crv: ECCurveType(rawValue: keyData.expectedCurveType)!,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url
            )

            XCTAssertEqual(key.keyType, .EC)
            XCTAssertEqual(key["kty"] ?? "", "EC")

            XCTAssertEqual(key.crv, ECCurveType(rawValue: keyData.expectedCurveType))
            XCTAssertEqual(key["crv"] ?? "", keyData.expectedCurveType)

            XCTAssertEqual(key.x, keyData.expectedXCoordinateBase64Url)
            XCTAssertEqual(key["x"] ?? "", keyData.expectedXCoordinateBase64Url)

            XCTAssertEqual(key.y, keyData.expectedYCoordinateBase64Url)
            XCTAssertEqual(key["y"] ?? "", keyData.expectedYCoordinateBase64Url)

            // kty, crv, x, y
            XCTAssertEqual(key.parameters.count, 4)

        }
    }

    func testInitPrivateKeyDirectlyWithoutAdditionalParameters() {
        allTestData.forEach { keyData in
            let key = try! ECPrivateKey(
                    crv: keyData.expectedCurveType,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url,
                    privateKey: keyData.expectedPrivateBase64Url
            )

            XCTAssertEqual(key.keyType, .EC)
            XCTAssertEqual(key["kty"] ?? "", "EC")

            XCTAssertEqual(key.crv, ECCurveType(rawValue: keyData.expectedCurveType))
            XCTAssertEqual(key["crv"] ?? "", keyData.expectedCurveType)

            XCTAssertEqual(key.x, keyData.expectedXCoordinateBase64Url)
            XCTAssertEqual(key["x"] ?? "", keyData.expectedXCoordinateBase64Url)

            XCTAssertEqual(key.y, keyData.expectedYCoordinateBase64Url)
            XCTAssertEqual(key["y"] ?? "", keyData.expectedYCoordinateBase64Url)

            XCTAssertEqual(key.privateKey, keyData.expectedPrivateBase64Url)
            XCTAssertEqual(key["d"] ?? "", keyData.expectedPrivateBase64Url)

            // kty, crv, x, y, d
            XCTAssertEqual(key.parameters.count, 5)
        }
    }

    func testPublicKeyKeyTypeIsPresent() {
        allTestData.forEach { keyData in
            let jwk = try! ECPublicKey(publicKey: keyData.publicKey)

            XCTAssertEqual(jwk.keyType, .EC)
            XCTAssertEqual(jwk[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.EC.rawValue)
            XCTAssertEqual(jwk.parameters[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.EC.rawValue)
        }
    }

    func testPrivateKeyKeyTypeIsPresent() {
        allTestData.forEach { keyData in
            let jwk = try! ECPrivateKey(
                    crv: keyData.expectedCurveType,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url,
                    privateKey: keyData.expectedPrivateBase64Url
            )

            XCTAssertEqual(jwk.keyType, .EC)
            XCTAssertEqual(jwk[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.EC.rawValue)
            XCTAssertEqual(jwk.parameters[JWKParameter.keyType.rawValue] ?? "", JWKKeyType.EC.rawValue)
        }
    }

    func testSettingAndGettingAdditionalParameter() {
        allTestData.forEach { keyData in
            let params = ["kid": "new on the block"]
            let jwk = try! ECPublicKey(publicKey: keyData.publicKey, additionalParameters: params)

            XCTAssertEqual(jwk["kid"] ?? "", "new on the block")
        }
    }

    func testPublicKeyAllParametersArePresentInDict() {
        allTestData.forEach { keyData in
            let params = ["kid": "new on the block", "use": "test"]
            let jwk = try! ECPublicKey(publicKey: keyData.publicKey, additionalParameters: params)

            XCTAssertEqual(jwk.parameters.count, 6)
        }
    }

    func testPrivateKeyAllParametersArePresentInDict() {
        allTestData.forEach { keyData in
            let params = ["kid": "new on the block", "use": "test"]
            let jwk = try! ECPrivateKey(
                    crv: keyData.expectedCurveType,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url,
                    privateKey: keyData.expectedPrivateBase64Url,
                    additionalParameters: params
            )

            XCTAssertEqual(jwk.parameters.count, 7)
        }
    }

    func testInvalidPrivateCurveType() {
        do {
            _ = try ECPrivateKey(crv: "P-255", x: "", y: "", privateKey: "")
        } catch JOSESwiftError.invalidCurvePointOctetLength {
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    @available(iOS 11.0, *)
    func testThumbprintPublicKey() {
        allTestData.forEach { keyData in
            let key = ECPublicKey(
                    crv: ECCurveType(rawValue: keyData.expectedCurveType)!,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url
            )

            XCTAssertEqual(try? key.thumbprint(), keyData.expectedThumbprint)
        }
    }

    @available(iOS 11.0, *)
    func testThumbprintPrivateKey() {
        allTestData.forEach { keyData in
            let key = try! ECPrivateKey(
                    crv: keyData.expectedCurveType,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url,
                    privateKey: keyData.expectedPrivateBase64Url
            )

            XCTAssertEqual(try? key.thumbprint(), keyData.expectedThumbprint)
        }
    }

    @available(iOS 11.0, *)
    func testAddPublicThumbprintToJWK() throws {
        try allTestData.forEach { keyData in
            let key = try ECPublicKey(
                    crv: ECCurveType(rawValue: keyData.expectedCurveType)!,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url
            ).withThumbprintAsKeyId()

            XCTAssertEqual(key.parameters[JWKParameter.keyIdentifier.rawValue], keyData.expectedThumbprint)
        }
    }

    @available(iOS 11.0, *)
    func testAddPublicThumbprintToJWKCopyParameters() throws {
        let useKey = "sig"
        try allTestData.forEach { keyData in
            let key = try ECPublicKey(
                    crv: ECCurveType(rawValue: keyData.expectedCurveType)!,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url,
                    additionalParameters: [JWKParameter.keyUse.rawValue: useKey]
            ).withThumbprintAsKeyId()

            XCTAssertEqual(key.parameters[JWKParameter.keyIdentifier.rawValue], keyData.expectedThumbprint)
            XCTAssertEqual(key.parameters[JWKParameter.keyUse.rawValue], useKey)
        }
    }

    @available(iOS 11.0, *)
    func testAddPrivateThumbprintToJWK() throws {
        try allTestData.forEach { keyData in
            let key = try ECPrivateKey(
                    crv: keyData.expectedCurveType,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url,
                    privateKey: keyData.expectedPrivateBase64Url
            ).withThumbprintAsKeyId()

            XCTAssertEqual(key.parameters[JWKParameter.keyIdentifier.rawValue], keyData.expectedThumbprint)
        }
    }

    @available(iOS 11.0, *)
    func testAddPrivateThumbprintToJWKCopyParameters() throws {
        let useKey = "sig"
        try allTestData.forEach { keyData in
            let key = try ECPrivateKey(
                    crv: keyData.expectedCurveType,
                    x: keyData.expectedXCoordinateBase64Url,
                    y: keyData.expectedYCoordinateBase64Url,
                    privateKey: keyData.expectedPrivateBase64Url,
                    additionalParameters: [JWKParameter.keyUse.rawValue: useKey]
            ).withThumbprintAsKeyId()

            XCTAssertEqual(key.parameters[JWKParameter.keyIdentifier.rawValue], keyData.expectedThumbprint)
            XCTAssertEqual(key.parameters[JWKParameter.keyUse.rawValue], useKey)
        }
    }
}
// swiftlint:enable force_unwrapping
