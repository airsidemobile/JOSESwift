//
//  ECDHTests.swift
//  Tests
//
//  Created by Mikael Rucinsky on 07.12.20.
//

import XCTest
@testable import JOSESwift

// swiftlint:disable force_unwrapping

class ECDHTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testEcdhP521() {

        let staticJwkData = """
        {
            "crv": "P-521",
            "d": "AUbbQiwCrudeMaY4yO-epS8Z733v_6iekDE7Pg6lAhT2L_7n6MA3TmDbFYzTJXgWyVLhsgZhXBqYn8xTyXM4Htai",
            "kty": "EC",
            "x": "AKyzPrkMEWef9WsWohYs-Z18SoPmgQE53fk6CUmJV9QEvZWhXDSrptZeOrro8oXM1D4hQoSVlH_48QyxXQn27wqa",
            "y": "AOWWwHV2nAFrOMGQfrh_TLj0bTHB8OVWfenbjVemgl2WdDhHFvvbkyYlAJid9X9FoazoHULmdo-zPoj-eVem4VCF"
        }
        """.data(using: .utf8)

        let ephermeralJwkData = """
        {
            "crv": "P-521",
            "d": "ASNphnyfafd_DTnTANzCX-HHmuttns5r3OlUkA5KVZcWhrGbnon23UfLgDFZqlD6m2tSLf1eOmGtX3RrJoF2Z-KJ",
            "kty": "EC",
            "x": "AXfHyCQgbohr3CRm-zNX0zUYriba2MHyduzaxOup5yzDO1hS-PhU0LqbaH2FECctCOYgktUKCDcyDAdkY1ZRszLb",
            "y": "AHf_b9y-pbudkqws0rPcYGb9uVoIxotxdV-AQs0jcO0QCbAnm-QPNeF9-9mOCj-fAElOoi8UOfT5QlgxVdp67MQW"
        }
        """.data(using: .utf8)

        let expectedData = Data([0, 224, 82, 100, 184, 24, 23, 138, 155, 73, 143, 68, 142, 226, 142, 110, 120, 220, 105, 106, 220, 85, 251, 114, 5, 204, 117, 169, 140, 138, 219, 35, 86, 248, 83, 154, 231, 135, 207, 180, 80, 37, 122, 50, 47, 105, 227, 145, 69, 175, 167, 180, 171, 178, 219, 130, 56, 120, 3, 241, 93, 136, 176, 18, 188, 168])

        let staticEcKey = try! ECPrivateKey(data: staticJwkData!)
        let ephermeralEcKey = try! ECPrivateKey(data: ephermeralJwkData!)
        let bobData = try! ecdhDeriveBits(for: ephermeralEcKey.getPrivate(), publicKey: staticEcKey.getPublic())
        let aliceData = try! ecdhDeriveBits(for: staticEcKey.getPrivate(), publicKey: ephermeralEcKey.getPublic())
        XCTAssertEqual(bobData, expectedData)
        XCTAssertEqual(aliceData, bobData)
    }

    func testEcdhP384() {
        let staticJwkData = """
        {
            "crv": "P-384",
            "d": "k_g-sn31X_dik5nb50L_a0YCB1no_mcjsuX0bZwP6VQv_skCoUng0VUn5h_eNVIs",
            "kty": "EC",
            "x": "OfppBnaeX-TT6Xn_h4snNNwkdN29H_zL1A47ta-xvJ-Nq8LUaVT-klKkhOWqCBJo",
            "y": "XPik7pebt5XmFIWxO9DWFLe16JIupLefjpuexAlJ3i0GlTGpzKRkOtGG-EElfj5c"
        }
        """.data(using: .utf8)

        let ephermeralJwkData = """
        {
            "crv": "P-384",
            "d": "Wjv7bhechF4t7Ujqs9YrM3rOpQYoJ1E0ZjVZaC3lAqE21nr8YRt8YDWB8jr5w66Q",
            "kty": "EC",
            "x": "lK4yQQb3kGyJ96JvBNJ7i7HPEermvIq7ZtyVFTsolPYIzEGvt-blROOQTHiNt69m",
            "y": "gbYJSaZ6ekVI1r3pbpDGIM7o4OP3k36RVMxKCbP6HuOvq3mAHO4Lr6nyTy3bogPc"
        }
        """.data(using: .utf8)

        let expectedData = Data([230, 105, 144, 136, 251, 105, 192, 113, 56, 83, 18, 77, 253, 246, 16, 220, 184, 123, 192, 83, 77, 64, 255, 78, 114, 215, 36, 153, 91, 35, 78, 172, 23, 100, 143, 14, 243, 240, 74, 114, 216, 253, 94, 254, 97, 149, 115, 196])

        let staticEcKey = try! ECPrivateKey(data: staticJwkData!)
        let ephermeralEcKey = try! ECPrivateKey(data: ephermeralJwkData!)
        let bobData = try! ecdhDeriveBits(for: ephermeralEcKey.getPrivate(), publicKey: staticEcKey.getPublic())
        let aliceData = try! ecdhDeriveBits(for: staticEcKey.getPrivate(), publicKey: ephermeralEcKey.getPublic())
        XCTAssertEqual(bobData, expectedData)
        XCTAssertEqual(aliceData, bobData)
    }

    func testEcdhP256() {
        let staticJwkData = """
        {
            "crv": "P-256",
            "d": "AbffgK370mWXIZrN6Z9fkbTtrTR7tEezt2Xrei4MBv4",
            "kty": "EC",
            "x": "DmcvVfpUDcEA1qEdqoYWin33fFeWE0gmJWZUINGb_9I",
            "y": "_Jt9LSkX3u-Vc3DfDq1svbfpkXCQN6Zx2QhygiHlghg"
        }
        """.data(using: .utf8)

        let ephermeralJwkData = """
        {
            "crv": "P-256",
            "d": "iRyhvwq_12htMLqxD7WxGxplPnM7qERKJ-Y9RQcLUi0",
            "kty": "EC",
            "x": "XPWOBbmFX4KqM--QywDwck0NNL2gheuvDgHK2r0sj6E",
            "y": "KvlPaC91qExYOUJcp8C_Ml4Tv43BtRBlTEZmLTpzGU4"
        }
        """.data(using: .utf8)

        let expectedData = Data([73, 222, 123, 31, 188, 213, 243, 252, 244, 226, 35, 24, 228, 238, 70, 152, 31, 249, 163, 201, 233, 219, 202, 33, 245, 140, 21, 169, 252, 199, 110, 177])

        let staticEcKey = try! ECPrivateKey(data: staticJwkData!)
        let ephermeralEcKey = try! ECPrivateKey(data: ephermeralJwkData!)
        let bobData = try! ecdhDeriveBits(for: ephermeralEcKey.getPrivate(), publicKey: staticEcKey.getPublic())
        let aliceData = try! ecdhDeriveBits(for: staticEcKey.getPrivate(), publicKey: ephermeralEcKey.getPublic())
        XCTAssertEqual(bobData, expectedData)
        XCTAssertEqual(aliceData, bobData)
    }

    func testDeriveKeyDataShoudTheSameP256() {
        let staticKey = try! ECKeyPair.generateWith(ECCurveType.P256)
        let ephermeralKey = try! ECKeyPair.generateWith(ECCurveType.P256)
        let data1 = try! ecdhDeriveBits(for: staticKey.getPrivate(), publicKey: ephermeralKey.getPublic())
        let data2 = try! ecdhDeriveBits(for: ephermeralKey.getPrivate(), publicKey: staticKey.getPublic())
        XCTAssertEqual(data1, data2)
    }

    func testDeriveKeyDataShoudTheSameP384() {
        let staticKey = try! ECKeyPair.generateWith(ECCurveType.P384)
        let ephermeralKey = try! ECKeyPair.generateWith(ECCurveType.P384)
        let data1 = try! ecdhDeriveBits(for: staticKey.getPrivate(), publicKey: ephermeralKey.getPublic())
        let data2 = try! ecdhDeriveBits(for: ephermeralKey.getPrivate(), publicKey: staticKey.getPublic())
        XCTAssertEqual(data1, data2)
    }

    func testDeriveKeyDataShoudTheSameP521() {
        let staticKey = try! ECKeyPair.generateWith(ECCurveType.P521)
        let ephermeralKey = try! ECKeyPair.generateWith(ECCurveType.P521)
        let data1 = try! ecdhDeriveBits(for: staticKey.getPrivate(), publicKey: ephermeralKey.getPublic())
        let data2 = try! ecdhDeriveBits(for: ephermeralKey.getPrivate(), publicKey: staticKey.getPublic())
        XCTAssertEqual(data1, data2)
    }

//    Concat KDF see https://tools.ietf.org/html/rfc7518#section-4.6.2
    func testConcatKDF() {
        let z = Data([
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
            38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
            140, 254, 144, 196])

        let algID = Data([0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77])

        let ptyUInfo = Data([0, 0, 0, 5, 65, 108, 105, 99, 101])
        let ptyVInfo = Data([0, 0, 0, 3, 66, 111, 98])

        let supPubInfo = Data([0, 0, 0, 128])
        let supPrivInfo = Data()

        let expected = Data([86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26])

        let concat = try! concatKDF(hash: Hash.SHA256,
                                    z: z,
                                    keyDataLen: 128,
                                    algorithmID: algID,
                                    partyUInfo: ptyUInfo,
                                    partyVInfo: ptyVInfo,
                                    suppPubInfo: supPubInfo,
                                    suppPrivInfo: supPrivInfo)

        XCTAssertEqual(String(data: expected, encoding: .utf16)!, String(data: concat, encoding: .utf16)!)
    }

    func testEcdhKeyAgreementCompute() {
        let aliceKey = try! ECPrivateKey(data: """
        {
            "crv": "P-256",
            "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
            "kty": "EC",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
        }
        """.data(using: .utf8)!)

        let bobKey = try! ECPrivateKey(data: """
        {
            "crv": "P-256",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
            "kty": "EC",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        }
        """.data(using: .utf8)!)

        let alg = KeyManagementAlgorithm.ECDH_ES
        let enc = ContentEncryptionAlgorithm.A256CBCHS512
        let apuData = "Alice".data(using: .utf8)!
        let apvData = "Bob".data(using: .utf8)!
        let expected = Data([57, 134, 170, 121, 246, 57, 100, 32, 229, 128, 229, 211, 137, 15, 98, 63, 238, 93, 69, 34, 48, 121, 41, 235, 153, 238, 52, 37, 160, 1, 236, 193, 117, 177, 117, 78, 63, 182, 68, 206, 130, 80, 52, 181, 98, 82, 62, 154, 136, 6, 188, 168, 215, 106, 250, 134, 30, 155, 121, 81, 88, 3, 34, 93])
        let data = try! keyAgreementCompute(with: alg,
                                            encryption: enc,
                                            privateKey: bobKey.getPrivate(),
                                            publicKey: aliceKey.getPublic(),
                                            apu: apuData,
                                            apv: apvData)
        XCTAssertEqual(data, expected)
    }

    func testPerformanceConcatKDF() {
        // This is an example of a performance test case.
        measure {
            let z = Data([
                158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
                38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
                140, 254, 144, 196])

            let algID = Data([0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77])

            let ptyUInfo = Data([0, 0, 0, 5, 65, 108, 105, 99, 101])
            let ptyVInfo = Data([0, 0, 0, 3, 66, 111, 98])

            let supPubInfo = Data([0, 0, 0, 128])
            let supPrivInfo = Data()
            do {
                let a = try concatKDF(hash: Hash.SHA256, z: z, keyDataLen: 128, algorithmID: algID, partyUInfo: ptyUInfo, partyVInfo: ptyVInfo, suppPubInfo: supPubInfo, suppPrivInfo: supPrivInfo)
                print(a)
            } catch {}
        }
    }
}
