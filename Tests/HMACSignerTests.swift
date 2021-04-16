//
//  HMACSignerTests.swift
//  Tests
//
//  Created by Tobias Hagemann on 14.04.21.
//

import XCTest
@testable import JOSESwift

class HMACSignerTests: HMACCryptoTestCase {
    private func _testSigning(algorithm: SignatureAlgorithm, expectedSignature: Data) {
        let signer = HMACSigner(algorithm: algorithm, key: testKey)
        let signature = try! signer.sign(testData)
        XCTAssertEqual(expectedSignature, signature)
    }

    func testSigning() {
        _testSigning(algorithm: .HS256, expectedSignature: hmac256TestOutput)
        _testSigning(algorithm: .HS384, expectedSignature: hmac384TestOutput)
        _testSigning(algorithm: .HS512, expectedSignature: hmac512TestOutput)
    }
}
