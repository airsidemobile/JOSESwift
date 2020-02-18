//
//  JWEAESKeyWrapTests.swift
//  Tests
//
//  Created by Daniel Egger on 18.02.20.
//

import XCTest
@testable import JOSESwift

// swiftlint:disable force_unwrapping

class JWEAESKeyWrapTests: XCTestCase {
    func testRoundtrip() throws {
        let symmetricKey = Data(base64URLEncoded: "GawgguFyGrWKav7AX4VKUg")!

        let header = JWEHeader(algorithm: .A128KW, encryptionAlgorithm: .A128CBCHS256)
        let payload = Payload("Live long and prosper.".data(using: .ascii)!)
        let encrypter = Encrypter(
            keyManagementAlgorithm: .A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256,
            encryptionKey: symmetricKey
        )!

        let jwe = try JWE(header: header, payload: payload, encrypter: encrypter)

        let decyrpter = Decrypter(
            keyManagementAlgorithm: .A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256,
            decryptionKey: symmetricKey
        )!

        let decryptedPayload = try jwe.decrypt(using: decyrpter)

        XCTAssertEqual(decryptedPayload.data(), payload.data())
    }

    func testRoundtripFailsWithWrongKey() throws {
        let symmetricKey = Data(base64URLEncoded: "GawgguFyGrWKav7AX4VKUg")!
        let wrongSymmetricKey = Data(base64URLEncoded: "WRONGuFyGrWKav7AX4VKUg")!

        let header = JWEHeader(algorithm: .A128KW, encryptionAlgorithm: .A128CBCHS256)
        let payload = Payload("Live long and prosper.".data(using: .ascii)!)
        let encrypter = Encrypter(
            keyManagementAlgorithm: .A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256,
            encryptionKey: symmetricKey
        )!

        let jwe = try JWE(header: header, payload: payload, encrypter: encrypter)

        let decyrpter = Decrypter(
            keyManagementAlgorithm: .A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256,
            decryptionKey: wrongSymmetricKey
        )!

        XCTAssertThrowsError(try jwe.decrypt(using: decyrpter))
    }
}
