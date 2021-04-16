// swiftlint:disable force_unwrapping
//
//  JWSHMACTests.swift
//  Tests
//
//  Created by Tobias Hagemann on 15.04.21.
//

import XCTest
@testable import JOSESwift

class JWSHMACTests: HMACCryptoTestCase {
    private func _testHMACDeserialization(algorithm: SignatureAlgorithm, compactSerializedJWS: String) {
        let jws = try! JWS(compactSerialization: compactSerializedJWS)
        XCTAssertEqual("{\"alg\":\"\(algorithm.rawValue)\"}", String(data: jws.header.data(), encoding: .utf8))
        XCTAssertEqual(message, String(data: jws.payload.data(), encoding: .utf8))

        let signer = Signer(signingAlgorithm: algorithm, privateKey: signingKey)!
        let signature = try! signer.sign(header: JWSHeader(algorithm: algorithm), payload: Payload(message.data(using: .utf8)!))
        XCTAssertEqual(jws.signature.data(), signature)
    }

    private func _testHMACSerializationValidationAndDeserialization(algorithm: SignatureAlgorithm) {
        let header = JWSHeader(algorithm: algorithm)
        let payload = Payload(message.data(using: .utf8)!)
        let signer = Signer(signingAlgorithm: algorithm, privateKey: signingKey)!
        let jws = try! JWS(header: header, payload: payload, signer: signer)
        let compactSerializedJWS = jws.compactSerializedString

        let secondJWS = try! JWS(compactSerialization: compactSerializedJWS)
        let verifier = Verifier(verifyingAlgorithm: algorithm, publicKey: signingKey)

        XCTAssertTrue(secondJWS.isValid(for: verifier!))
        XCTAssertEqual(message, String(data: secondJWS.payload.data(), encoding: .utf8))
        XCTAssertEqual("{\"alg\":\"\(algorithm.rawValue)\"}", String(data: jws.header.data(), encoding: .utf8))
    }

    func testHMACDeserialization() {
        _testHMACDeserialization(algorithm: .HS256, compactSerializedJWS: compactSerializedJWSHS256Const)
        _testHMACDeserialization(algorithm: .HS384, compactSerializedJWS: compactSerializedJWSHS384Const)
        _testHMACDeserialization(algorithm: .HS512, compactSerializedJWS: compactSerializedJWSHS512Const)
    }

    func testHMACSerializationValidationAndDeserialization() {
        _testHMACSerializationValidationAndDeserialization(algorithm: .HS256)
        _testHMACSerializationValidationAndDeserialization(algorithm: .HS384)
        _testHMACSerializationValidationAndDeserialization(algorithm: .HS512)
    }
}
