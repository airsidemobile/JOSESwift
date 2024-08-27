// swiftlint:disable force_unwrapping
//
//  PBES2KeyEncryptionModeTests.swift
//  Tests
//
//  Created by Daniel Egger on 23.08.24.
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

class PBES2KeyEncryptionModeTests: XCTestCase {
    let testDummyPassword = "1234567890"

    func testDefaultSaltInputLength() throws {
        let jweHeader = JWEHeader(
            keyManagementAlgorithm: .PBES2_HS256_A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256
        )

        let keyManagementMode = PBES2KeyEncryptionMode(
            keyManagementAlgorithm: jweHeader.keyManagementAlgorithm!,
            contentEncryptionAlgorithm: jweHeader.contentEncryptionAlgorithm!,
            password: testDummyPassword
        )

        XCTAssertEqual(keyManagementMode.pbes2SaltInputLength, 8)

        let context = try! keyManagementMode.determineContentEncryptionKey(with: jweHeader)

        XCTAssertEqual(context.jweHeader!.p2s!.count, 8)
    }

    func testOkCustomSaltInputLengthGetsAccepted() throws {
        let jweHeader = JWEHeader(
            keyManagementAlgorithm: .PBES2_HS256_A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256
        )

        let keyManagementMode = PBES2KeyEncryptionMode(
            keyManagementAlgorithm: jweHeader.keyManagementAlgorithm!,
            contentEncryptionAlgorithm: jweHeader.contentEncryptionAlgorithm!,
            password: testDummyPassword,
            pbes2SaltInputLength: 16
        )

        XCTAssertEqual(keyManagementMode.pbes2SaltInputLength, 16)

        let context = try! keyManagementMode.determineContentEncryptionKey(with: jweHeader)

        XCTAssertEqual(context.jweHeader!.p2s!.count, 16)
    }

    func testWrongCustomSaltInputLengthGetsIgnored() throws {
        let jweHeader = JWEHeader(
            keyManagementAlgorithm: .PBES2_HS256_A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256
        )

        let keyManagementMode = PBES2KeyEncryptionMode(
            keyManagementAlgorithm: jweHeader.keyManagementAlgorithm!,
            contentEncryptionAlgorithm: jweHeader.contentEncryptionAlgorithm!,
            password: testDummyPassword,
            pbes2SaltInputLength: 7
        )

        XCTAssertEqual(keyManagementMode.pbes2SaltInputLength, 8)

        let context = try! keyManagementMode.determineContentEncryptionKey(with: jweHeader)

        XCTAssertEqual(context.jweHeader!.p2s!.count, 8)
    }

    func testHeaderSaltInputGetsIgnored() throws {
        var jweHeader = JWEHeader(
            keyManagementAlgorithm: .PBES2_HS256_A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256
        )

        jweHeader.p2s = Data([UInt8].init(repeating: 0x00, count: 16))
        XCTAssertEqual(jweHeader.p2s!.count, 16)

        let keyManagementMode = PBES2KeyEncryptionMode(
            keyManagementAlgorithm: jweHeader.keyManagementAlgorithm!,
            contentEncryptionAlgorithm: jweHeader.contentEncryptionAlgorithm!,
            password: testDummyPassword
        )

        XCTAssertEqual(keyManagementMode.pbes2SaltInputLength, 8)

        let context = try! keyManagementMode.determineContentEncryptionKey(with: jweHeader)

        XCTAssertEqual(context.jweHeader!.p2s!.count, 8)
    }

    func testDefaultIterationCount() throws {
        let jweHeader = JWEHeader(
            keyManagementAlgorithm: .PBES2_HS256_A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256
        )

        let keyManagementMode = PBES2KeyEncryptionMode(
            keyManagementAlgorithm: jweHeader.keyManagementAlgorithm!,
            contentEncryptionAlgorithm: jweHeader.contentEncryptionAlgorithm!,
            password: testDummyPassword
        )

        let context = try! keyManagementMode.determineContentEncryptionKey(with: jweHeader)

        XCTAssertEqual(context.jweHeader!.p2c!, 1_000)
    }

    func testCustomIterationCountGetsAccepted() throws {
        var jweHeader = JWEHeader(
            keyManagementAlgorithm: .PBES2_HS256_A128KW,
            contentEncryptionAlgorithm: .A128CBCHS256
        )

        jweHeader.p2c = 1_000_000

        let keyManagementMode = PBES2KeyEncryptionMode(
            keyManagementAlgorithm: jweHeader.keyManagementAlgorithm!,
            contentEncryptionAlgorithm: jweHeader.contentEncryptionAlgorithm!,
            password: testDummyPassword
        )

        let context = try! keyManagementMode.determineContentEncryptionKey(with: jweHeader)

        XCTAssertEqual(context.jweHeader!.p2c!, 1_000_000)
    }
}
// swiftlint:enable force_unwrapping
