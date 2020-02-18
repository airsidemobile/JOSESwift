//
//  AESKeyWrapKeyManagementModeTests.swift
//  Tests
//
//  Created by Daniel Egger on 18.02.20.
//

// swiftlint:disable force_unwrapping

import XCTest
import CommonCrypto
@testable import JOSESwift

class AESKeyWrapKeyManagementModeTests: XCTestCase {
    let keyManagementModeAlgorithms: [KeyManagementAlgorithm] = [.A128KW, .A192KW, .A256KW]

    let symmetricKeys: [KeyManagementAlgorithm: Data] = [
        KeyManagementAlgorithm.A128KW: Data(count: 128 / 8),
        KeyManagementAlgorithm.A192KW: Data(count: 192 / 8),
        KeyManagementAlgorithm.A256KW: Data(count: 256 / 8)
    ]

    func testGeneratesRandomContentEncryptionKeyOnEachCall() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[algorithm]!
            )

            let (cek1, _) = try keyEncryption.determineContentEncryptionKey()
            let (cek2, _) = try keyEncryption.determineContentEncryptionKey()

            XCTAssertNotEqual(cek1, cek2)
        }
    }

    func testFailsForWrongKeySiye() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: Data(count: 10)
            )

            XCTAssertThrowsError(try keyEncryption.determineContentEncryptionKey())
        }
    }

    func testEncryptsContentEncryptionKey() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[algorithm]!
            )

            let (cek, encryptedKey) = try keyEncryption.determineContentEncryptionKey()

            XCTAssertNotEqual(cek, encryptedKey)

            let decryptedKey = ccAESKeyUnwrap(
                wrappedKey: encryptedKey,
                keyEncryptionKey: symmetricKeys[algorithm]!,
                iv: Data(bytes: CCrfc3394_iv, count: CCrfc3394_ivLen)
            )

            XCTAssertEqual(decryptedKey.data, cek)
        }
    }

    func testEncryptsContentEncryptionKeyOnlyForProvidedKey() throws {
        for algorithm in keyManagementModeAlgorithms {
            let keyEncryption = AESKeyWrappingMode(
                keyManagementAlgorithm: algorithm,
                contentEncryptionAlgorithm: .A128CBCHS256,
                sharedSymmetricKey: symmetricKeys[algorithm]!
            )

            let (cek, encryptedKey) = try keyEncryption.determineContentEncryptionKey()

            XCTAssertNotEqual(cek, encryptedKey)

            let wrongKey = Data(repeating: 1, count: symmetricKeys[algorithm]!.count)

            let decryptedKey = ccAESKeyUnwrap(
                wrappedKey: encryptedKey,
                keyEncryptionKey: wrongKey,
                iv: Data(bytes: CCrfc3394_iv, count: CCrfc3394_ivLen)
            )

            XCTAssertNotEqual(decryptedKey.data, cek)
        }
    }

    func testGeneratesContentEncryptionKeyOfCorrectLength() throws {
        let contentEncryptionAlgorithms: [ContentEncryptionAlgorithm] = [.A128CBCHS256, .A256CBCHS512]

        for alg in keyManagementModeAlgorithms {
            for enc in contentEncryptionAlgorithms {
                let keyEncryption = AESKeyWrappingMode(
                    keyManagementAlgorithm: alg,
                    contentEncryptionAlgorithm: enc,
                    sharedSymmetricKey: symmetricKeys[alg]!
                )

                let (cek, _) = try keyEncryption.determineContentEncryptionKey()

                XCTAssertEqual(cek.count, enc.keyLength)
            }
        }
    }

}

private func ccAESKeyUnwrap(
       wrappedKey: Data,
       keyEncryptionKey: Data,
       iv: Data
   ) -> (data: Data, status: Int32) {
       let alg = CCWrappingAlgorithm(kCCWRAPAES)

       var rawKeyLength: size_t = CCSymmetricUnwrappedSize(alg, wrappedKey.count)
       var rawKey = Data(count: rawKeyLength)

       let status = rawKey.withUnsafeMutableBytes { rawKeyBytes in
           wrappedKey.withUnsafeBytes { wrappedKeyBytes in
               iv.withUnsafeBytes { ivBytes in
                   keyEncryptionKey.withUnsafeBytes { keyEncryptionKeyBytes -> Int32 in
                       guard
                           let rawKeyBytes = rawKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                           let wrappedKeyBytes = wrappedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                           let ivBytes = ivBytes.bindMemory(to: UInt8.self).baseAddress,
                           let keyEncryptionKeyBytes = keyEncryptionKeyBytes.bindMemory(to: UInt8.self).baseAddress
                       else {
                           return Int32(kCCMemoryFailure)
                       }
                       return CCSymmetricKeyUnwrap(
                           alg,
                           ivBytes, iv.count,
                           keyEncryptionKeyBytes, keyEncryptionKey.count,
                           wrappedKeyBytes, wrappedKey.count,
                           rawKeyBytes, &rawKeyLength
                       )
                   }
               }
           }
       }

       if status == kCCSuccess {
           rawKey.removeSubrange(rawKeyLength..<rawKey.count)
       }

       return (rawKey, status)
   }
