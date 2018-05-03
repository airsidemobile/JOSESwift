//
//  JWSValidationTests.swift
//  Tests
//
//  Created by Daniel Egger on 22.02.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
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

class JWSValidationTests: CryptoTestCase {

    func testIsValid() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSConst)

        XCTAssertTrue(jws.isValid(for: publicKeyAlice2048!))
    }

    func testIsValidIsFalseForInvalidAlg() {
        // Replaces alg "RS512" with alg "FOOBAR" in header
        let malformedSerialization = compactSerializedJWSConst.replacingOccurrences(of: "eyJhbGciOiJSUzUxMiJ9", with: "eyJhbGciOiJGT09CQVIifQ")

        let jws = try! JWS(compactSerialization: malformedSerialization)

        XCTAssertFalse(jws.isValid(for: publicKeyAlice2048!))
    }

    func testIsValidIsFalseForWrongSignature() {
        // Replaces part of the signature, making it invalid
        let malformedSerialization = compactSerializedJWSConst.replacingOccurrences(of: "dar", with: "foo")

        let jws = try! JWS(compactSerialization: malformedSerialization)

        XCTAssertFalse(jws.isValid(for: publicKeyAlice2048!))
    }

    func testIsValidIsFalseForWrongKey() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSConst)

        XCTAssertFalse(jws.isValid(for: publicKey4096!))
    }

    func testValidatesDoesNotThrowForValidSignature() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSConst)

        XCTAssertNoThrow(try jws.validate(with: publicKeyAlice2048!))
    }

    func testValidatesReturnsJWS() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSConst)

        let validatedJWS = try! jws.validate(with: publicKeyAlice2048!)

        XCTAssertEqual(validatedJWS.compactSerializedString, compactSerializedJWSConst)
    }

    func testValidatesThrowsForInvalidAlg() {
        // Replaces alg "RS512" with alg "FOOBAR" in header
        let malformedSerialization = compactSerializedJWSConst.replacingOccurrences(of: "eyJhbGciOiJSUzUxMiJ9", with: "eyJhbGciOiJGT09CQVIifQ")

        let jws = try! JWS(compactSerialization: malformedSerialization)

        XCTAssertThrowsError(try jws.validate(with: publicKeyAlice2048!))
    }

    func testValidatesThrowsForWrongSignature() {
        // Replaces part of the signature, making it invalid
        let malformedSerialization = compactSerializedJWSConst.replacingOccurrences(of: "dar", with: "foo")

        let jws = try! JWS(compactSerialization: malformedSerialization)

        XCTAssertThrowsError(try jws.validate(with: publicKeyAlice2048!))
    }

    func testValidatesThrowsForWrongKey() {
        let jws = try! JWS(compactSerialization: compactSerializedJWSConst)

        XCTAssertThrowsError(try jws.validate(with: publicKey4096!))
    }
    
}
