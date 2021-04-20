//
//  HMACVerifierTests.swift
//  Tests
//
//  Created by Tobias Hagemann on 14.04.21.
//

import XCTest
@testable import JOSESwift

class HMACVerifierTests: HMACCryptoTestCase {
    private func _testVerifying(algorithm: SignatureAlgorithm, expectedSignature: Data) {
        let verifier = HMACVerifier(algorithm: algorithm, key: testKey)
        XCTAssertTrue(try! verifier.verify(testData, against: expectedSignature))
    }

    func testVerifying() {
        _testVerifying(algorithm: .HS256, expectedSignature: hmac256TestOutput)
        _testVerifying(algorithm: .HS384, expectedSignature: hmac384TestOutput)
        _testVerifying(algorithm: .HS512, expectedSignature: hmac512TestOutput)
    }
}
