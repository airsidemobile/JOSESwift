//
//  JWEDirectEncryptionTests.swift
//  Tests
//
//  Created by Daniel Egger on 04.07.18.
//

import XCTest
@testable import JOSESwift

class JWEDirectEncryptionTests: XCTestCase {
    
    func testExample() {
        let symmetricKey = try! SecureRandom.generate(count: SymmetricKeyAlgorithm.A256CBCHS512.keyLength)

        let header = JWEHeader(algorithm: .direct, encryptionAlgorithm: .A256CBCHS512)

        let payload = Payload("So Secret! 🔥🌵".data(using: .utf8)!)

        let encrypter = Encrypter(keyEncryptionAlgorithm: .direct, encryptionKey: symmetricKey, contentEncyptionAlgorithm: .A256CBCHS512)!

        let jwe = try! JWE(header: header, payload: payload, encrypter: encrypter)

        let serialization = jwe.compactSerializedString

        let j = try! JWE(compactSerialization: serialization)
        let p = try! j.decrypt(with: symmetricKey)
        let message = String(data: p.data(), encoding: .utf8)!

        print(message)
    }

    func testExampleDecrypt() {
        let symmetricKey = Data(base64URLEncoded: "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueo8tVpVM3sG4AR6HeaXDPR_eRkEVdyQ126CEUTkgYoHgg")!

        let jwe = try! JWE(compactSerialization: "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiZGlyIn0..oIVW1sX2UKUm2WSRizxaKg.AS0v0ctVUYwHW2nTLAatC7j4lTIzw4OtE5MFM4ahCmA.B0MQ8Hh2Miv3tq5QCmtk6xROPezHZDSvylLsDnuNKTQ")

        let p = try! jwe.decrypt(with: symmetricKey)
        let message = String(data: p.data(), encoding: .utf8)

        print(message!)
    }
    
}
