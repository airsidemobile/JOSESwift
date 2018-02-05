//
//  JWKRSADecodingTests.swift
//  Tests
//
//  Created by Daniel Egger on 05.02.18.
//

import XCTest
@testable import SwiftJOSE

class JWKRSADencodingTests: CryptoTestCase {

    let publicKeyJSON = """
        {\
        \"kty\":\"RSA\",\
        \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV\
        4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdA\
        ZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEg\
        U8awapJzKnqDKgw\",\
        \"e\":\"AQAB\",\
        \"alg\":\"RS256\",\
        \"kid\":\"2011-04-29\"\
        }
        """.data(using: .utf8)!

    let privateKeyJSON = """
        {\
        \"kty\":\"RSA\",\
        \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV\
        4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdA\
        ZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEg\
        U8awapJzKnqDKgw\",\
        \"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXS\
        zUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl\
        3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqn\
        OYtqc0X4jfcKoAC8Q\",\
        \"e\":\"AQAB\",\
        \"alg\":\"RS256\",\
        \"kid\":\"2011-04-29\"\
        }
        """.data(using: .utf8)!

    // MARK: - Public Key Tests

    func testDecodingPublicKey() {
        let jwk = try? JSONDecoder().decode(RSAPublicKey.self, from: publicKeyJSON)

        XCTAssertNotNil(jwk)

        XCTAssertEqual(jwk!.keyType, .RSA)
        XCTAssertEqual(jwk!["kty"] ?? "", "RSA")
        XCTAssertEqual(jwk!.modulus, """
            0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n\
            3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zg\
            dAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFC\
            ur-kEgU8awapJzKnqDKgw
            """
        )
        XCTAssertEqual(jwk!.exponent, "AQAB")
        XCTAssertEqual(jwk!["alg"] ?? "", "RS256")
        XCTAssertEqual(jwk!["kid"] ?? "", "2011-04-29")
    }

    func testDecodingPublicKeyMissingKeyType() {
        let keyType = "\"kty\":\"RSA\","

        let wrongPublicKey = String(data: publicKeyJSON, encoding: .utf8)!.replacingOccurrences(of: keyType, with: "").data(using: .utf8)!

        do {
            let _ = try JSONDecoder().decode(RSAPublicKey.self, from: wrongPublicKey)
        } catch DecodingError.keyNotFound(let key, _) {
            XCTAssertEqual(key.stringValue, JWKParameter.keyType.rawValue)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testDecodingPublicKeyMissingModulus() {
        let modulus = """
            \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZ\
            CiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9\
            c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF4\
            4-csFCur-kEgU8awapJzKnqDKgw\",
            """

        let wrongPublicKey = String(data: publicKeyJSON, encoding: .utf8)!.replacingOccurrences(of: modulus, with: "").data(using: .utf8)!

        do {
            let _ = try JSONDecoder().decode(RSAPublicKey.self, from: wrongPublicKey)
        } catch DecodingError.keyNotFound(let key, _) {
            XCTAssertEqual(key.stringValue, RSAKeyParameter.modulus.rawValue)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testDecodingPublicKeyMissingExponent() {
        let exponent = "\"e\":\"AQAB\","

        let wrongPublicKey = String(data: publicKeyJSON, encoding: .utf8)!.replacingOccurrences(of: exponent, with: "").data(using: .utf8)!

        do {
            let _ = try JSONDecoder().decode(RSAPublicKey.self, from: wrongPublicKey)
        } catch DecodingError.keyNotFound(let key, _) {
            XCTAssertEqual(key.stringValue, RSAKeyParameter.exponent.rawValue)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testDecodingPublicKeyWrongDataFormat() {
        let wrongPublicKey = "{\"kty\":\"RSA\"".data(using: .utf8)!

        do {
            let _ = try JSONDecoder().decode(RSAPublicKey.self, from: wrongPublicKey)
        } catch DecodingError.dataCorrupted(let context) {
            XCTAssertEqual(context.debugDescription, "The given data was not valid JSON.")
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    // MARK: - Private Key Tests

    func testDecodingPrivateKey() {
        let jwk = try? JSONDecoder().decode(RSAPrivateKey.self, from: privateKeyJSON)

        XCTAssertNotNil(jwk)

        XCTAssertEqual(jwk!.keyType, .RSA)
        XCTAssertEqual(jwk!["kty"] ?? "", "RSA")
        XCTAssertEqual(jwk!.modulus, """
            0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n\
            3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zg\
            dAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFC\
            ur-kEgU8awapJzKnqDKgw
            """
        )
        XCTAssertEqual(jwk!.privateExponent, """
            X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvx\
            T0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl\
            3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y\
            6mqnOYtqc0X4jfcKoAC8Q
            """
        )
        XCTAssertEqual(jwk!.exponent, "AQAB")
        XCTAssertEqual(jwk!["alg"] ?? "", "RS256")
        XCTAssertEqual(jwk!["kid"] ?? "", "2011-04-29")
    }

    func testDecodingPrivateKeyMissingKeyType() {
        let keyType = "\"kty\":\"RSA\","

        let wrongPrivateKey = String(data: privateKeyJSON, encoding: .utf8)!.replacingOccurrences(of: keyType, with: "").data(using: .utf8)!

        do {
            let _ = try JSONDecoder().decode(RSAPrivateKey.self, from: wrongPrivateKey)
        } catch DecodingError.keyNotFound(let key, _) {
            XCTAssertEqual(key.stringValue, JWKParameter.keyType.rawValue)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testDecodingPrivateKeyMissingModulus() {
        let modulus = """
            \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZ\
            CiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9\
            c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF4\
            4-csFCur-kEgU8awapJzKnqDKgw\",
            """

        let wrongPrivateKey = String(data: privateKeyJSON, encoding: .utf8)!.replacingOccurrences(of: modulus, with: "").data(using: .utf8)!

        do {
            let _ = try JSONDecoder().decode(RSAPrivateKey.self, from: wrongPrivateKey)
        } catch DecodingError.keyNotFound(let key, _) {
            XCTAssertEqual(key.stringValue, RSAKeyParameter.modulus.rawValue)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testDecodingPrivateKeyMissingExponent() {
        let exponent = "\"e\":\"AQAB\","

        let wrongPrivateKey = String(data: privateKeyJSON, encoding: .utf8)!.replacingOccurrences(of: exponent, with: "").data(using: .utf8)!

        do {
            let _ = try JSONDecoder().decode(RSAPrivateKey.self, from: wrongPrivateKey)
        } catch DecodingError.keyNotFound(let key, _) {
            XCTAssertEqual(key.stringValue, RSAKeyParameter.exponent.rawValue)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testDecodingPrivateKeyMissingPrivateExponent() {
        let privateExponent = """
            \"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXS\
            zUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl\
            3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqn\
            OYtqc0X4jfcKoAC8Q\",
            """

        let wrongPrivateKey = String(data: privateKeyJSON, encoding: .utf8)!.replacingOccurrences(of: privateExponent, with: "").data(using: .utf8)!

        do {
            let _ = try JSONDecoder().decode(RSAPrivateKey.self, from: wrongPrivateKey)
        } catch DecodingError.keyNotFound(let key, _) {
            XCTAssertEqual(key.stringValue, RSAKeyParameter.privateExponent.rawValue)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testDecodingPrivateKeyWrongDataFormat() {
        let wrongPrivateKey = "{\"kty\":\"RSA\"".data(using: .utf8)!

        do {
            let _ = try JSONDecoder().decode(RSAPrivateKey.self, from: wrongPrivateKey)
        } catch DecodingError.dataCorrupted(let context) {
            XCTAssertEqual(context.debugDescription, "The given data was not valid JSON.")
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

}
