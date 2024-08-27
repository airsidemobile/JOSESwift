// swiftlint:disable force_unwrapping
//
//  JWSCustomSignerVerifierTests.swift
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

class JWSCustomSignerVerifierTests: XCTestCase {
    private struct NoOpSigner: SignerProtocol {
        var algorithm: SignatureAlgorithm = .HS256

        func sign(_ signingInput: Data) throws -> Data {
            return Data()
        }
    }

    private struct NoOpVerifyer: VerifierProtocol {
        var algorithm: SignatureAlgorithm = .HS256

        func verify(_ signingInput: Data, against signature: Data) throws -> Bool {
            return false
        }
    }

    func testCustomSigner() throws {
        let header = JWSHeader(algorithm: .HS256)
        let payload = Payload("Summer, Sun, Cactus".data(using: .utf8)!)
        let customSigner = Signer(customSigner: NoOpSigner())

        let jws = try JWS(header: header, payload: payload, signer: customSigner)

        XCTAssertEqual(jws.signature, Data())
    }

    func testCustomVerifier() throws {
        let testDummySigningKey = "not-so-secret".data(using: .utf8)!

        let header = JWSHeader(algorithm: .HS256)
        let payload = Payload("Summer, Sun, Cactus".data(using: .utf8)!)
        let signer = Signer(signatureAlgorithm: .HS256, key: testDummySigningKey)!
        let joseVerifier = Verifier(signatureAlgorithm: .HS256, key: testDummySigningKey)!
        let customVerifier = Verifier(customVerifier: NoOpVerifyer())

        let jws = try JWS(header: header, payload: payload, signer: signer)

        XCTAssertTrue(jws.isValid(for: joseVerifier))
        XCTAssertFalse(jws.isValid(for: customVerifier))
    }
}
// swiftlint:enable force_unwrapping
