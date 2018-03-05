//
//  CryptoTestCase.swift
//  Tests
//
//  Created by Carol Capek on 02.11.17.
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

class CryptoTestCase: XCTestCase {
    let message = "The true sign of intelligence is not knowledge but imagination."
    let privateKey2048Tag = "com.airsidemobile.JOSESwift.testPrivateKey2048"
    let privateKey4096Tag = "com.airsidemobile.JOSESwift.testPrivateKey4096"

    var privateKey2048: SecKey?
    var publicKey2048: SecKey?

    var privateKey4096: SecKey?
    var publicKey4096: SecKey?

    let compactSerializedJWSConst = """
        eyJhbGciOiJSUzUxMiJ9.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.dar4u\
        Qfhg7HpAXDrFJEP3T6cPePUIstu3tCLiz-HBEx1yAQXxLweQrKOYvIWOlt_HfxjjhxfGDoSXjnQMVHZTJaAYFNtK382pfOKpJAxE6UvkhLtvS-A\
        6BKLWMS_aUVgqizOIXH0IeuVz1COpSLlsQ5KICUaqsxYyPfD28vbbQ9IfJ4RyJmSqEEx-M8BY2r4v_HHL-kyvjqGbSoF7o9Z6Cg1CetPJ5OHPBM\
        XZa_Aj3LkNWn1GSw5B4WQueb8E0uJVAzLSNbxA-ZNowlOgDtKHOEkwbZu6zj7WvLEm8xovgmAha_y7HssoXnH26Nu-8RMUYw-LXUJz6Fny1F_xc\
        v_TA
        """

    var publicKey2048Data: Data!
    var publicKey4096Data: Data!

    // Generated by OpenSSL for `publicKey` (without leading 0x00).
    let expectedModulus2048Base64 = """
        iADzxMJ-l_NIVPbqz9eoBenUCCUiNNfZ37c6gUJwWEfJRyGchAe96m4GLr3pzj2A3Io4MSKf9dDWMak6qkR_XYljSjZBbXAhQan2sIB5qyPW7NJ\
        7XpJWHoaHdHwEN9Cj29zL-WtFk6lC1rPDmNPRTmRy0ct4EP4YJ49PMcoKJQKbog79ws1KdDzNGTVVkEgLB4VOlW8A164kaK8-xMUxTqySUtigLT\
        DUMqjQ_81SFgsNnMUqnxp87bKD77olYBia88r8V2YXEx1Jgl8t22gNNh6lkN8BDqlkb_Y2uS-c7vlYIfSH6WYkVsSPsrA-GLLRo_R07FGxvs2M5\
        gZxnmlvew
        """

    // Generated by OpenSSL for `publicKey4096` (without leading 0x00).
    let expectedModulus4096Base64 = """
        v-rKTWfCkZmUjQsppCM7u3DVz2bYaoFp_c5r4lwLJXvP9S99dAVMG5YHiJAHVLSMDIm0O5WTNR_1pvwPA57zal2Gss9q-a4imx-f5pyC8e2vtro\
        zS3hejcZyYSSdotJCSfGWaSh1_8CyIyrAoMfHLt4-YHH7U6N1h7nqIzt5thybBObsBkTiul5hMqxf02SEqxZpPfv0AKMKPontcxuO1DRgQUkcPk\
        ljKSysurNwmET3Dl50NkuYhCsUe5mz5yu9GHT6HER-47helljRF4d1d4RTkzk1BnXy1ZbmsdTN9vewmYuAqACLAVdPiK4ejw46l8aSOclazireR\
        Q04ismklfP1wc3CJ532CZ4PKf0tfflOmhEAXyjF3VwQsj0yl_4S5JphoutWkq_hN1AVX6K3F9xEENm4dddaetFYWgQpjjth8UwM_Svm7aflR9f-\
        g_1xjxvaPAG-ir-NqIsFeVpk8OJ-ZKg1YMKmYIcyRptnn1XNdJz5724r1xge_oPzfFxYqGEeAmRhPaB5HgvS8ysF0YhtskJFGsB6P3DxFm-1RgU\
        g2IlwBa-8gGvkwZ5W0Hy1gyZo-BZVHG2G-un2nJd_t4L-io1bgBG3sE-vOmV98L6tTzlKdyroa9xi45QRiN0SzA0an0x1fdJzSkh-FcVIQ0ELDJ\
        DgruI_mX4M_u3yazs
        """

    // Generated by OpenSSL for `publicKey`.
    let expectedExponentBase64 = "AQAB"

    // Dummy data since we don't (yet) implement any `ExpressibleAsRSAPrivateKeyComponents`.
    let expectedPrivateExponentBase64 = "MHZ4Li4uS2d3"

    // Generated by OpenSSL for `publicKey` (without leading 0x00).
    let expectedModulus2048Data = Data(bytes: [
        136, 0, 243, 196, 194, 126, 151, 243, 72, 84, 246, 234, 207, 215, 168, 5, 233, 212, 8, 37, 34, 52, 215, 217,
        223, 183, 58, 129, 66, 112, 88, 71, 201, 71, 33, 156, 132, 7, 189, 234, 110, 6, 46, 189, 233, 206, 61, 128, 220,
        138, 56, 49, 34, 159, 245, 208, 214, 49, 169, 58, 170, 68, 127, 93, 137, 99, 74, 54, 65, 109, 112, 33, 65, 169,
        246, 176, 128, 121, 171, 35, 214, 236, 210, 123, 94, 146, 86, 30, 134, 135, 116, 124, 4, 55, 208, 163, 219, 220,
        203, 249, 107, 69, 147, 169, 66, 214, 179, 195, 152, 211, 209, 78, 100, 114, 209, 203, 120, 16, 254, 24, 39,
        143, 79, 49, 202, 10, 37, 2, 155, 162, 14, 253, 194, 205, 74, 116, 60, 205, 25, 53, 85, 144, 72, 11, 7, 133, 78,
        149, 111, 0, 215, 174, 36, 104, 175, 62, 196, 197, 49, 78, 172, 146, 82, 216, 160, 45, 48, 212, 50, 168, 208,
        255, 205, 82, 22, 11, 13, 156, 197, 42, 159, 26, 124, 237, 178, 131, 239, 186, 37, 96, 24, 154, 243, 202, 252,
        87, 102, 23, 19, 29, 73, 130, 95, 45, 219, 104, 13, 54, 30, 165, 144, 223, 1, 14, 169, 100, 111, 246, 54, 185,
        47, 156, 238, 249, 88, 33, 244, 135, 233, 102, 36, 86, 196, 143, 178, 176, 62, 24, 178, 209, 163, 244, 116, 236,
        81, 177, 190, 205, 140, 230, 6, 113, 158, 105, 111, 123
    ])

    // Generated by OpenSSL for `publicKey4096` (without leading 0x00).
    let expectedModulus4096Data = Data(bytes: [
        191, 234, 202, 77, 103, 194, 145, 153, 148, 141, 11, 41, 164, 35, 59, 187, 112, 213, 207, 102, 216, 106, 129,
        105, 253, 206, 107, 226, 92, 11, 37, 123, 207, 245, 47, 125, 116, 5, 76, 27, 150, 7, 136, 144, 7, 84, 180, 140,
        12, 137, 180, 59, 149, 147, 53, 31, 245, 166, 252, 15, 3, 158, 243, 106, 93, 134, 178, 207, 106, 249, 174, 34,
        155, 31, 159, 230, 156, 130, 241, 237, 175, 182, 186, 51, 75, 120, 94, 141, 198, 114, 97, 36, 157, 162, 210, 66,
        73, 241, 150, 105, 40, 117, 255, 192, 178, 35, 42, 192, 160, 199, 199, 46, 222, 62, 96, 113, 251, 83, 163, 117,
        135, 185, 234, 35, 59, 121, 182, 28, 155, 4, 230, 236, 6, 68, 226, 186, 94, 97, 50, 172, 95, 211, 100, 132, 171,
        22, 105, 61, 251, 244, 0, 163, 10, 62, 137, 237, 115, 27, 142, 212, 52, 96, 65, 73, 28, 62, 73, 99, 41, 44, 172,
        186, 179, 112, 152, 68, 247, 14, 94, 116, 54, 75, 152, 132, 43, 20, 123, 153, 179, 231, 43, 189, 24, 116, 250,
        28, 68, 126, 227, 184, 94, 150, 88, 209, 23, 135, 117, 119, 132, 83, 147, 57, 53, 6, 117, 242, 213, 150, 230,
        177, 212, 205, 246, 247, 176, 153, 139, 128, 168, 0, 139, 1, 87, 79, 136, 174, 30, 143, 14, 58, 151, 198, 146,
        57, 201, 90, 206, 42, 222, 69, 13, 56, 138, 201, 164, 149, 243, 245, 193, 205, 194, 39, 157, 246, 9, 158, 15,
        41, 253, 45, 125, 249, 78, 154, 17, 0, 95, 40, 197, 221, 92, 16, 178, 61, 50, 151, 254, 18, 228, 154, 97, 162,
        235, 86, 146, 175, 225, 55, 80, 21, 95, 162, 183, 23, 220, 68, 16, 217, 184, 117, 215, 90, 122, 209, 88, 90, 4,
        41, 142, 59, 97, 241, 76, 12, 253, 43, 230, 237, 167, 229, 71, 215, 254, 131, 253, 113, 143, 27, 218, 60, 1,
        190, 138, 191, 141, 168, 139, 5, 121, 90, 100, 240, 226, 126, 100, 168, 53, 96, 194, 166, 96, 135, 50, 70, 155,
        103, 159, 85, 205, 116, 156, 249, 239, 110, 43, 215, 24, 30, 254, 131, 243, 124, 92, 88, 168, 97, 30, 2, 100,
        97, 61, 160, 121, 30, 11, 210, 243, 43, 5, 209, 136, 109, 178, 66, 69, 26, 192, 122, 63, 112, 241, 22, 111, 181,
        70, 5, 32, 216, 137, 112, 5, 175, 188, 128, 107, 228, 193, 158, 86, 208, 124, 181, 131, 38, 104, 248, 22, 85,
        28, 109, 134, 250, 233, 246, 156, 151, 127, 183, 130, 254, 138, 141, 91, 128, 17, 183, 176, 79, 175, 58, 101,
        125, 240, 190, 173, 79, 57, 74, 119, 42, 232, 107, 220, 98, 227, 148, 17, 136, 221, 18, 204, 13, 26, 159, 76,
        117, 125, 210, 115, 74, 72, 126, 21, 197, 72, 67, 65, 11, 12, 144, 224, 174, 226, 63, 153, 126, 12, 254, 237,
        242, 107, 59
    ])

    // Generated by OpenSSL for `publicKey`.
    let expectedExponentData = Data(bytes: [ 1, 0, 1 ])

    override func setUp() {
        super.setUp()
        setupKeys()
    }

    override func tearDown() {
        super.tearDown()
    }

    private func setupKeys() {
        if
            let path = Bundle(for: type(of: self)).path(forResource: "TestKey", ofType: "plist"),
            let keyDict = NSDictionary(contentsOfFile: path),
            let keyData2048 = Data(base64Encoded: keyDict[privateKey2048Tag] as! String),
            let keyData4096 = Data(base64Encoded: keyDict[privateKey4096Tag] as! String)
        {

            // 2048

            let keyPair2048 = setupSecKeyPair(size: 2048, data: keyData2048, tag: privateKey2048Tag)!

            privateKey2048 = keyPair2048.privateKey
            publicKey2048 = keyPair2048.publicKey
            publicKey2048Data = SecKeyCopyExternalRepresentation(publicKey2048!, nil)! as Data

            // 4096

            let keyPair4096 = setupSecKeyPair(size: 4096, data: keyData4096, tag: privateKey4096Tag)!

            privateKey4096 = keyPair4096.privateKey
            publicKey4096 = keyPair4096.publicKey
            publicKey4096Data = SecKeyCopyExternalRepresentation(publicKey4096!, nil)! as Data
        }
    }

    private func setupSecKeyPair(size: Int, data: Data, tag: String) -> (privateKey: SecKey, publicKey: SecKey)? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: size,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrApplicationTag as String: tag
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            print(error!)
            return nil
        }

        let publicKey = SecKeyCopyPublicKey(privateKey)!

        return (privateKey, publicKey)
    }
}

extension String {

    func hexadecimalToData() -> Data? {
        var data = Data(capacity: count / 2)

        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, range: NSMakeRange(0, utf16.count)) { match, _, _ in
            let byteString = (self as NSString).substring(with: match!.range)
            var num = UInt8(byteString, radix: 16)!
            data.append(&num, count: 1)
        }

        guard data.count > 0 else { return nil }

        return data
    }

}

extension Data {
    func toHexadecimal() -> String {
        return map { String(format: "%02x", $0) }
            .joined(separator: "")
    }
}
