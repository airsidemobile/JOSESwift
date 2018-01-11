//
//  JWKParsingTests.swift
//  Tests
//
//  Created by Daniel Egger on 11.01.18.
//

import XCTest
@testable import SwiftJOSE

extension JWKError: Equatable { }
extension JWKError {
    public static func ==(lhs: JWKError, rhs: JWKError) -> Bool {
        switch (lhs, rhs) {
        case (.RequiredJWKParameterMissing(let leftParameter), .RequiredJWKParameterMissing(let rightParameter)):
            return leftParameter == rightParameter
        case (.RequiredRSAParameterMissing(let leftParameter), .RequiredRSAParameterMissing(let rightParameter)):
            return leftParameter == rightParameter
        case (.JWKDataNotInTheRightFormat, .JWKDataNotInTheRightFormat):
            return true
        default:
            return false
        }
    }
}

class JWKRSAParsingTests: XCTestCase {
    
    let publicKeyString = """
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
        """

    let privateKeyString = """
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
        """

    // MARK: - Public Key Tests

    func testParsingPublicKey() {
        let jwk = try? JWKParser().parse(publicKeyString)

        XCTAssertNotNil(jwk)

        let rsa = jwk as? RSAPublicKey

        XCTAssertNotNil(rsa)

        XCTAssertEqual(rsa!.keyType, .RSA)
        XCTAssertEqual(rsa!["kty"] as? String ?? "", "RSA")
        XCTAssertEqual(rsa!.modulus, """
            0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n\
            3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zg\
            dAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFC\
            ur-kEgU8awapJzKnqDKgw
            """
        )
        XCTAssertEqual(rsa!.exponent, "AQAB")
        XCTAssertEqual(rsa!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(rsa!["kid"] as? String ?? "", "2011-04-29")
    }

    func testParsingPublicKeyMissingKeyType() {
        let keyType = "\"kty\":\"RSA\","

        let wrongPublicKeyString = publicKeyString.replacingOccurrences(of: keyType, with: "")

        XCTAssertThrowsError(try JWKParser().parse(wrongPublicKeyString)) { (error) -> Void in
            XCTAssertEqual(error as! JWKError, JWKError.RequiredJWKParameterMissing(parameter: "kty"))
        }
    }

    func testParsingPublicKeyMissingModulus() {
        let modulus = """
            \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZ\
            CiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9\
            c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF4\
            4-csFCur-kEgU8awapJzKnqDKgw\",
            """

        let wrongPublicKeyString = publicKeyString.replacingOccurrences(of: modulus, with: "")

        XCTAssertThrowsError(try JWKParser().parse(wrongPublicKeyString)) { (error) -> Void in
            XCTAssertEqual(error as! JWKError, JWKError.RequiredRSAParameterMissing(parameter: "n"))
        }
    }

    func testParsingPublicKeyMissingExponent() {
        let exponent = "\"e\":\"AQAB\","

        let wrongPublicKeyString = publicKeyString.replacingOccurrences(of: exponent, with: "")

        XCTAssertThrowsError(try JWKParser().parse(wrongPublicKeyString)) { (error) -> Void in
            XCTAssertEqual(error as! JWKError, JWKError.RequiredRSAParameterMissing(parameter: "e"))
        }
    }

    func testParsingPublicKeyWrongDataFormat() {
        XCTAssertThrowsError(try JWKParser().parse("{\"kty\":\"RSA\"")) { (error) -> Void in
            XCTAssertEqual(error as! JWKError, JWKError.JWKDataNotInTheRightFormat)
        }
    }

    // MARK: - Private Key Tests

    func testParsingPrivateKey() {
        let jwk = try? JWKParser().parse(privateKeyString)

        XCTAssertNotNil(jwk)

        let rsa = jwk as? RSAPrivateKey

        XCTAssertNotNil(rsa)
        XCTAssertNotNil(jwk as? RSAKeyPair)

        XCTAssertEqual(rsa!.keyType, .RSA)
        XCTAssertEqual(rsa!["kty"] as? String ?? "", "RSA")
        XCTAssertEqual(rsa!.modulus, """
            0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n\
            3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zg\
            dAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFC\
            ur-kEgU8awapJzKnqDKgw
            """
        )
        XCTAssertEqual(rsa!.privateExponent, """
            X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvx\
            T0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl\
            3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y\
            6mqnOYtqc0X4jfcKoAC8Q
            """
        )
        XCTAssertEqual(rsa!.exponent, "AQAB")
        XCTAssertEqual(rsa!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(rsa!["kid"] as? String ?? "", "2011-04-29")
    }

    func testParsingPrivateKeyMissingKeyType() {
        let keyType = "\"kty\":\"RSA\","

        let wrongPrivateKeyString = privateKeyString.replacingOccurrences(of: keyType, with: "")

        XCTAssertThrowsError(try JWKParser().parse(wrongPrivateKeyString)) { (error) -> Void in
            XCTAssertEqual(error as! JWKError, JWKError.RequiredJWKParameterMissing(parameter: "kty"))
        }
    }

    func testParsingPrivateKeyMissingModulus() {
        let modulus = """
            \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXj\
            BZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnY\
            b9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1j\
            F44-csFCur-kEgU8awapJzKnqDKgw\",
            """

        let wrongPrivateKeyString = privateKeyString.replacingOccurrences(of: modulus, with: "")

        XCTAssertThrowsError(try JWKParser().parse(wrongPrivateKeyString)) { (error) -> Void in
            XCTAssertEqual(error as! JWKError, JWKError.RequiredRSAParameterMissing(parameter: "n"))
        }
    }

    func testParsingPrivateKeyMissingExponent() {
        let exponent = "\"e\":\"AQAB\","

        let wrongPrivateKeyString = privateKeyString.replacingOccurrences(of: exponent, with: "")

        XCTAssertThrowsError(try JWKParser().parse(wrongPrivateKeyString)) { (error) -> Void in
            XCTAssertEqual(error as! JWKError, JWKError.RequiredRSAParameterMissing(parameter: "e"))
        }
    }

    func testParsingPrivateKeyMissingPrivateExponentBecomesPublicKey() {
        let privateExponent = """
            \"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXS\
            zUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl\
            3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqn\
            OYtqc0X4jfcKoAC8Q\",
            """

        let wrongPrivateKeyString = privateKeyString.replacingOccurrences(of: privateExponent, with: "")
        let jwk = try? JWKParser().parse(wrongPrivateKeyString)

        XCTAssertNotNil(jwk)

        let rsa = jwk! as? RSAPublicKey

        XCTAssertNotNil(rsa)

        XCTAssertEqual(rsa!.keyType, .RSA)
        XCTAssertEqual(rsa!["kty"] as? String ?? "", "RSA")
        XCTAssertEqual(rsa!.modulus, """
            0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n\
            3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zg\
            dAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFC\
            ur-kEgU8awapJzKnqDKgw
            """
        )
        XCTAssertEqual(rsa!.exponent, "AQAB")
        XCTAssertEqual(rsa!["alg"] as? String ?? "", "RS256")
        XCTAssertEqual(rsa!["kid"] as? String ?? "", "2011-04-29")
    }

    func testParsingPrivateKeyWrongDataFormat() {
        XCTAssertThrowsError(try JWKParser().parse("{\"kty\":\"RSA\"")) { (error) -> Void in
            XCTAssertEqual(error as! JWKError, JWKError.JWKDataNotInTheRightFormat)
        }
    }
    
}
