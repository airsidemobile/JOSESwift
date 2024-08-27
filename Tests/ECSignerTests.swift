// swiftlint:disable force_unwrapping
//
//  ECSignerTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 21.10.18.
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

class ECSignerTests: ECCryptoTestCase {

    private func _testSigning(algorithm: SignatureAlgorithm, keyData: ECTestKeyData) {
        let messageData = message.data(using: .utf8)!
        let signer = ECSigner(algorithm: algorithm, privateKey: keyData.privateKey)
        let signature = try! signer.sign(messageData)
        let signature2 = try! signer.sign(messageData)

        // As any two signing invocations will have different nonces, it is impossible to use pre-generated data from a
        // trusted implementation (e.g. openssl) to verify the signature.  Instead we will validate by verifying the
        // signature.  This assumes that the verification implementation is correct.
        XCTAssertNotEqual(signature.base64URLEncodedString(), signature2.base64URLEncodedString())
        let verifier = ECVerifier(algorithm: algorithm, publicKey: keyData.publicKey)
        let verified = (try? verifier.verify(messageData, against: signature)) ?? false
        XCTAssertTrue(verified)
    }

    func testSigning() {
        _testSigning(algorithm: .ES256, keyData: p256)
        _testSigning(algorithm: .ES384, keyData: p384)
        _testSigning(algorithm: .ES512, keyData: p521)
    }
}
// swiftlint:enable force_unwrapping
