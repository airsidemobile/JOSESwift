// swiftlint:disable force_unwrapping
//
//  JWSValidationTests.swift
//  Tests
//
//  Created by Daniel Egger on 22.02.18.
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

class JWSValidationTests: RSACryptoTestCase {
    func testValidatesWithExplicitVerifier() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSRS512Const)

        let verifier = Verifier(signatureAlgorithm: .RS512, key: publicKeyAlice2048!)!

        XCTAssertNoThrow(try jws.validate(using: verifier))
    }

    func testValidatesWithExplicitVerifierReturnsJWS() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSRS512Const)

        let verifier = Verifier(signatureAlgorithm: .RS512, key: publicKeyAlice2048!)!

        let returnedJWS = try! jws.validate(using: verifier)

        XCTAssertEqual(returnedJWS.compactSerializedString, jws.compactSerializedString)
    }

    func testValidatesWithExplicitVerifierCatchesWrongVerifierAlgorithm() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSRS512Const)

        let verifier = Verifier(signatureAlgorithm: .RS256, key: publicKeyAlice2048!)!

        XCTAssertThrowsError(try jws.validate(using: verifier), "verifying with wrong verifier algorithm") { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.signingAlgorithmMismatch)
        }
    }

    func testValidatesWithExplicitVerifierCatchesWrongHeaderAlgorithm() {
        // Replaces alg "RS512" with alg "HS256" in header
        let malformedSerialization = compactSerializedJWSRS512Const.replacingOccurrences(of: "eyJhbGciOiJSUzUxMiJ9", with: "eyJhbGciOiJIUzI1NiJ9")

        let jws = try! JWS(compactSerialization: malformedSerialization)

        let verifier = Verifier(signatureAlgorithm: .RS512, key: publicKeyAlice2048!)!

        XCTAssertThrowsError(try jws.validate(using: verifier), "verifying with wrong header algorithm") { error in
            XCTAssertEqual(error as! JOSESwiftError, JOSESwiftError.signingAlgorithmMismatch)
        }
    }

    func testValidatesWithExplicitVerifierFailsForWrongKey() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSRS512Const)

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]

        var error: Unmanaged<CFError>?

        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print(error!)
            return
        }

        let verifier = Verifier(signatureAlgorithm: .RS512, key: SecKeyCopyPublicKey(key)!)!

        XCTAssertThrowsError(try jws.validate(using: verifier))
    }

    func testValidatesWithExplicitVerifierFailsForWrongSignature() {
        // Replaces part of the signature, making it invalid
        let malformedSerialization = compactSerializedJWSRS512Const.replacingOccurrences(of: "dar", with: "foo")

        let jws = try! JWS(compactSerialization: malformedSerialization)

        let verifier = Verifier(signatureAlgorithm: .RS512, key: publicKeyAlice2048!)!

        XCTAssertThrowsError(try jws.validate(using: verifier))
    }

    func testIsValidWithExplicitVerifier() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSRS512Const)

        let verifier = Verifier(signatureAlgorithm: .RS512, key: publicKeyAlice2048!)

        XCTAssertTrue(jws.isValid(for: verifier!))
    }

    func testIsValidWithExplicitVerifierIsFalseForInvalidAlg() {
        // Replaces alg "RS512" with alg "FOOBAR" in header
        let malformedSerialization = compactSerializedJWSRS512Const.replacingOccurrences(of: "eyJhbGciOiJSUzUxMiJ9", with: "eyJhbGciOiJGT09CQVIifQ")

        let jws = try! JWS(compactSerialization: malformedSerialization)

        let verifier = Verifier(signatureAlgorithm: .RS512, key: publicKeyAlice2048!)

        XCTAssertFalse(jws.isValid(for: verifier!))
    }

    func testIsValidWithExplicitVerifierIsFalseForWrongSignature() {
        // Replaces part of the signature, making it invalid
        let malformedSerialization = compactSerializedJWSRS512Const.replacingOccurrences(of: "dar", with: "foo")

        let jws = try! JWS(compactSerialization: malformedSerialization)

        let verifier = Verifier(signatureAlgorithm: .RS512, key: publicKeyAlice2048!)

        XCTAssertFalse(jws.isValid(for: verifier!))
    }

    func testIsValidWithExplicitVerifierIsFalseForWrongKey() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSRS512Const)

        let verifier = Verifier(signatureAlgorithm: .RS512, key: publicKey4096!)

        XCTAssertFalse(jws.isValid(for: verifier!))
    }

    func testIsValidWithExplicitVerifierCatchesWrongVerifierAlgorithm() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSRS512Const)

        let verifier = Verifier(signatureAlgorithm: .RS256, key: publicKeyAlice2048!)!

        XCTAssertFalse(jws.isValid(for: verifier))
    }

    func testIsValidWithExplicitVerifierCatchesWrongHeaderAlgorithm() {
        // Replaces alg "RS512" with alg "HS256" in header
        let malformedSerialization = compactSerializedJWSRS512Const.replacingOccurrences(of: "eyJhbGciOiJSUzUxMiJ9", with: "eyJhbGciOiJIUzI1NiJ9")

        let jws = try! JWS(compactSerialization: malformedSerialization)

        let verifier = Verifier(signatureAlgorithm: .RS512, key: publicKeyAlice2048!)!

        XCTAssertFalse(jws.isValid(for: verifier))
    }

}

extension JOSESwiftError: Equatable {
    public static func == (lhs: JOSESwiftError, rhs: JOSESwiftError) -> Bool {
        switch (lhs, rhs) {
        case (.verifyingFailed(let lhs), .verifyingFailed(let rhs)):
            return lhs == rhs
        case (.decryptingFailed(let lhs), .decryptingFailed(let rhs)):
            return lhs == rhs
        case (.encryptingFailed(let lhs), .encryptingFailed(let rhs)):
            return lhs == rhs
        default:
            return lhs.localizedDescription == rhs.localizedDescription
        }
    }
}
// swiftlint:enable force_unwrapping
