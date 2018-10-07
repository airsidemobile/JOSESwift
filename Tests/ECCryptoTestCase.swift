//
//  ECCryptoTestCase.swift
//  Tests
//
//  Created by Jarrod Moldrich on 07.10.18.
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
import Foundation

class ECCryptoTestCase: CryptoTestCase {

    // Keys generated and values extracted using the following openssl commands:
    //
    // key parameters - `openssl ecparam -out test.keyparam -name <curve>`
    //                   where <curve> is `prime256v1` or `secp384r1` or `secp521r1`
    // private key - `openssl ecparam -in test.keyparam -genkey -noout -out test.key`
    // public key - `openssl ec -in test.key -pubout -out testpub.key`
    // private component - `cat test.key | openssl base64 -d | openssl asn1parse -inform DER`
    // coordinates (excluding prefix 0x40) - `cat testpub.key | openssl base64 -d | openssl asn1parse -inform DER -dump`
    //
    // Compact serialization generated at https://jwt.io

    // MARK: P-256

    // todo: make this data structure generic
    let privateKey256Tag = "com.airsidemobile.JOSESwift.testECPrivateKey256"
    var privateKey256: SecKey?
    var publicKey256: SecKey?
    var publicKey256Data: Data!

    let compactSerializedJWSHeaderEC256Const =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"
    let compactSerializedJWSPayloadEC256Const =
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgTmFtZSIsImlhdCI6MTUxNjIzOTAyMn0"
    let compactSerializedJWSSignatureEC256Const =
            "hR5LbQJWDSAlUMS6MszGR8wJwR7i3pH8yeUubbz-hXr9sqMhnYNWPbb-uHuUDlbSswS9or6ORXIaNyhBBiDGXA"
    let compactSerializedJWSEC256Const =
            """
            eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgTmFtZSIsImlhdCI6MTUxNjIzOT\
            AyMn0.hR5LbQJWDSAlUMS6MszGR8wJwR7i3pH8yeUubbz-hXr9sqMhnYNWPbb-uHuUDlbSswS9or6ORXIaNyhBBiDGXA
            """

    let expectedEC256PrivateOctetString = Data(bytes: [
        0x12, 0xEA, 0x41, 0x29, 0x15, 0x4E, 0x48, 0x2E, 0x01, 0x92, 0xA5, 0x28, 0x89, 0x70, 0xAD, 0x56, 0x82, 0x19,
        0xBF, 0xC8, 0x25, 0x5E, 0xF2, 0x03, 0x0E, 0x4C, 0x1D, 0xCF, 0x46, 0x8A, 0x7E, 0x25
    ])

    let expectedEC256XCoordinate = Data(bytes: [
        0x4e, 0xf4, 0x34, 0xfe, 0x6b, 0x83, 0xca, 0xf4, 0xb8, 0x45, 0x7f, 0x5b, 0x26, 0x6f, 0x11, 0xcf, 0x2f, 0x57,
        0x4e, 0x94, 0x86, 0xef, 0x1c, 0x28, 0xdc, 0x57, 0xe0, 0xbb, 0xc3, 0xaa, 0xec, 0xe6,
    ])

    let expectedEC256YCoordinate = Data(bytes: [
        0xb1, 0xa3, 0x6b, 0xe2, 0x13, 0x37, 0xaa, 0xba, 0x23, 0x4a, 0x86, 0x38, 0x79, 0xa3, 0xb5, 0x58, 0x65, 0x67,
        0x6b, 0x9c, 0x96, 0xfc, 0x8e, 0x04, 0xa9, 0xd1, 0x50, 0xe1, 0x34, 0x65, 0xf2, 0x24
    ])

    // MARK: P-384

    let privateKey384Tag = "com.airsidemobile.JOSESwift.testECPrivateKey384"
    var privateKey384: SecKey?
    var publicKey384: SecKey?
    var publicKey384Data: Data!

    let compactSerializedJWSHeaderEC384Const =
            "eyJhbGciOiJFUzM4NCIsInR5cCI6I"
    let compactSerializedJWSPayloadEC384Const =
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgTmFtZSIsImlhdCI6MTUxNjIzOTAyMn0"
    let compactSerializedJWSSignatureEC384Const =
            """
            kZAiZyMd-9GPyabPgyQkygfF8d2xfhqHP3H_RvhgJPw01qxltG90Ii8kmd8MuPDRaGrymqQ2HChFKLdi5B4oy69lbFFOeL0-HE0gXm8Jx9d\
            hYmtb-jgsmPD4z8WrY2Wt
            """
    let compactSerializedJWSEC384Const =
            """
            eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgTmFtZSIsImlhdCI6MTUxNjIzOT\
            AyMn0.kZAiZyMd-9GPyabPgyQkygfF8d2xfhqHP3H_RvhgJPw01qxltG90Ii8kmd8MuPDRaGrymqQ2HChFKLdi5B4oy69lbFFOeL0-HE0gX\
            m8Jx9dhYmtb-jgsmPD4z8WrY2Wt
            """

    let expectedEC384PrivateOctetString = Data(bytes: [
        0xF9, 0x51, 0xCA, 0x86, 0xEF, 0x60, 0x8B, 0xAB, 0x42, 0xEB, 0xD3, 0x68, 0x6D, 0x8A, 0x47, 0xD9, 0x35, 0x97,
        0x13, 0x50, 0x7F, 0xE4, 0x80, 0xE7, 0xA6, 0xFC, 0xD0, 0x36, 0xA4, 0xB5, 0xD6, 0x7E, 0xA6, 0xE9, 0x6C, 0x36,
        0xD1, 0xF7, 0x80, 0xC4, 0x83, 0xB6, 0x51, 0x61, 0x5B, 0x76, 0x34, 0xA9
    ])

    let expectedEC384XCoordinate = Data(bytes: [
        0x9b, 0xb9, 0x5c, 0x37, 0x1e, 0x03, 0xdf, 0xa2, 0xdd, 0x7d, 0x7f, 0x8c, 0xa0, 0x30, 0x8a, 0x1b, 0x4e, 0x48,
        0xee, 0x50, 0xaf, 0xf4, 0x0b, 0x53, 0x37, 0xa9, 0xff, 0xbb, 0xc4, 0x6c, 0x8a, 0x3b, 0x7e, 0x26, 0x9c, 0xfd,
        0x24, 0x13, 0x21, 0x48, 0xfa, 0xd2, 0x12, 0x66, 0x75, 0x76, 0xf0, 0x9f
    ])

    let expectedEC384YCoordinate = Data(bytes: [
        0x87, 0x7c, 0xe4, 0x7f, 0xd7, 0x9a, 0x1d, 0xc2, 0x7b, 0x0f, 0x0e, 0xd2, 0x30, 0xf7, 0xca, 0xc0, 0x9d, 0x8f,
        0x12, 0x01, 0xd8, 0x79, 0x9f, 0x8f, 0xfa, 0xf3, 0xb1, 0x94, 0x14, 0xbf, 0x3a, 0xc0, 0x71, 0xed, 0x11, 0x73,
        0xfb, 0x23, 0x5a, 0x9f, 0x57, 0xbf, 0x3f, 0x48, 0x52, 0xf8, 0xb8, 0x0d
    ])

    // MARK: P-512

    let privateKey512Tag = "com.airsidemobile.JOSESwift.testECPrivateKey512"
    var privateKey512: SecKey?
    var publicKey512: SecKey?
    var publicKey512Data: Data!

    let compactSerializedJWSHeaderEC512Const =
            "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9"
    let compactSerializedJWSPayloadEC512Const =
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgTmFtZSIsImlhdCI6MTUxNjIzOTAyMn0"
    let compactSerializedJWSSignatureEC512Const =
            """
            AVmz_yYS5Hpb-rOoIJxL1w3tw2CLxb5px7VtC6x47gldrBddhm6PgLcuzoUX8e5tNb-wzUcaTZY1m3v1L1y8M85nAPxArD8tSqIMTAMi7kR\
            a8u6femrnRZSef3xZYtVtJ-_HXFPbAxwysZEypz1UaA_GgT2leYxtykujCI8fk3JhRpaH
            """
    let compactSerializedJWSEC512Const =
            """
            eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgTmFtZSIsImlhdCI6MTUxNjIzOT\
            AyMn0.AVmz_yYS5Hpb-rOoIJxL1w3tw2CLxb5px7VtC6x47gldrBddhm6PgLcuzoUX8e5tNb-wzUcaTZY1m3v1L1y8M85nAPxArD8tSqIMT\
            AMi7kRa8u6femrnRZSef3xZYtVtJ-_HXFPbAxwysZEypz1UaA_GgT2leYxtykujCI8fk3JhRpaH
            """

    let expectedEC512PrivateOctetString = Data(bytes: [
        0x01, 0xB6, 0x0C, 0x5E, 0x0C, 0xB9, 0x21, 0xE5, 0xB7, 0xD2, 0xB8, 0x24, 0x70, 0x1B, 0x13, 0xB2, 0x42, 0x57,
        0x5C, 0x22, 0xD9, 0x8D, 0x48, 0xF9, 0x35, 0xCA, 0xA6, 0x7E, 0x61, 0x19, 0x2F, 0x94, 0x66, 0x07, 0x80, 0x0C,
        0xEE, 0x6D, 0x3B, 0xA9, 0x8B, 0xA0, 0x7E, 0x5C, 0xF3, 0xC7, 0xCE, 0xBD, 0x85, 0xED, 0x61, 0xE8, 0xDD, 0xCA,
        0x2D, 0xB8, 0x9A, 0x03, 0x6D, 0x22, 0x13, 0x14, 0xF1, 0x5B, 0x17, 0x2E
    ])

    let expectedEC512XCoordinate = Data(bytes: [
        0x01, 0x0b, 0xbf, 0xe7, 0x32, 0xe4, 0x12, 0xb1, 0xab, 0x94, 0xd5, 0xeb, 0x7b, 0x63, 0x49, 0xbf, 0x2c, 0x9d,
        0x13, 0x3d, 0x1e, 0xe2, 0x0a, 0x48, 0x24, 0x7d, 0xa3, 0xc9, 0x2e, 0x2d, 0xca, 0xc4, 0xe5, 0xc1, 0x14, 0x96,
        0xd5, 0x42, 0x75, 0x7d, 0x49, 0x05, 0xe1, 0xbc, 0x82, 0x15, 0xc2, 0x80, 0xc8, 0xca, 0xbc, 0xb2, 0xd0, 0xff,
        0x98, 0xdd, 0x1b, 0xf3, 0xc8, 0x06, 0x9f, 0xb5, 0xbc, 0x77, 0xac, 0x83
    ])

    let expectedEC512YCoordinate = Data(bytes: [
        0x01, 0x27, 0x96, 0xce, 0xf3, 0xc3, 0xfe, 0xfa, 0x20, 0x2d, 0x89, 0x13, 0xd4, 0x69, 0x32, 0x5c, 0x4a, 0x70,
        0x47, 0x75, 0x7d, 0xe2, 0x12, 0x95, 0x0a, 0xb5, 0x86, 0x34, 0xb1, 0x6f, 0x94, 0x02, 0x7e, 0x0a, 0x98, 0x06,
        0x3b, 0x65, 0xc0, 0xfc, 0xc9, 0xef, 0x8f, 0x0a, 0x02, 0x37, 0x35, 0x7c, 0x90, 0x49, 0x4a, 0xcf, 0x61, 0xbb,
        0x2b, 0x7b, 0x61, 0xc7, 0x36, 0xa6, 0x7c, 0x9a, 0x2d, 0xfa, 0x56, 0x21
    ])

    override func setupKeys() {
        // todo: make generic function

        // 256

        var keyData256: Data = Data([0x04])
        keyData256.append(expectedEC256XCoordinate)
        keyData256.append(expectedEC256YCoordinate)
        keyData256.append(expectedEC256PrivateOctetString)

        let keyPair256 = setupSecKeyPair(
                type: kSecAttrKeyTypeECSECPrimeRandom as String,
                size: 256,
                data: keyData256,
                tag: privateKey256Tag)!

        privateKey256 = keyPair256.privateKey
        publicKey256 = keyPair256.publicKey
        publicKey256Data = SecKeyCopyExternalRepresentation(publicKey256!, nil)! as Data
        XCTAssertNotNil(publicKey256Data)

        // 384

        var keyData384 = Data(bytes: [0x04])
        keyData384.append(expectedEC384XCoordinate)
        keyData384.append(expectedEC384YCoordinate)
        keyData384.append(expectedEC384PrivateOctetString)

        let keyPair384 = setupSecKeyPair(
                type: kSecAttrKeyTypeECSECPrimeRandom as String,
                size: 384,
                data: keyData384,
                tag: privateKey384Tag)!

        privateKey384 = keyPair384.privateKey
        publicKey384 = keyPair384.publicKey
        publicKey384Data = SecKeyCopyExternalRepresentation(publicKey384!, nil)! as Data
        XCTAssertNotNil(publicKey384Data)

        // 512

        var keyData512 = Data(bytes: [0x04])
        keyData512.append(expectedEC512XCoordinate)
        keyData512.append(expectedEC512YCoordinate)
        keyData512.append(expectedEC512PrivateOctetString)

        let keyPair512 = setupSecKeyPair(
                type: kSecAttrKeyTypeECSECPrimeRandom as String,
                size: 512,
                data: keyData512,
                tag: privateKey512Tag)!

        privateKey512 = keyPair512.privateKey
        publicKey512 = keyPair512.publicKey
        publicKey512Data = SecKeyCopyExternalRepresentation(publicKey512!, nil)! as Data
        XCTAssertNotNil(publicKey512Data)
    }

}

