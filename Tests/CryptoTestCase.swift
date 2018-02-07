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
    let privateKeyTag = "com.airsidemobile.SwiftJOSE.testPrivateKey"
    var privateKey: SecKey?
    var publicKey: SecKey?

    let compactSerializedJWSConst = """
        eyJhbGciOiJSUzUxMiJ9.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.dar4u\
        Qfhg7HpAXDrFJEP3T6cPePUIstu3tCLiz-HBEx1yAQXxLweQrKOYvIWOlt_HfxjjhxfGDoSXjnQMVHZTJaAYFNtK382pfOKpJAxE6UvkhLtvS-A\
        6BKLWMS_aUVgqizOIXH0IeuVz1COpSLlsQ5KICUaqsxYyPfD28vbbQ9IfJ4RyJmSqEEx-M8BY2r4v_HHL-kyvjqGbSoF7o9Z6Cg1CetPJ5OHPBM\
        XZa_Aj3LkNWn1GSw5B4WQueb8E0uJVAzLSNbxA-ZNowlOgDtKHOEkwbZu6zj7WvLEm8xovgmAha_y7HssoXnH26Nu-8RMUYw-LXUJz6Fny1F_xc\
        v_TA
        """

    let publicKey2048Data = Data(base64Encoded: """
        MIIBCgKCAQEAiADzxMJ+l/NIVPbqz9eoBenUCCUiNNfZ37c6gUJwWEfJRyGchAe9\
        6m4GLr3pzj2A3Io4MSKf9dDWMak6qkR/XYljSjZBbXAhQan2sIB5qyPW7NJ7XpJW\
        HoaHdHwEN9Cj29zL+WtFk6lC1rPDmNPRTmRy0ct4EP4YJ49PMcoKJQKbog79ws1K\
        dDzNGTVVkEgLB4VOlW8A164kaK8+xMUxTqySUtigLTDUMqjQ/81SFgsNnMUqnxp8\
        7bKD77olYBia88r8V2YXEx1Jgl8t22gNNh6lkN8BDqlkb/Y2uS+c7vlYIfSH6WYk\
        VsSPsrA+GLLRo/R07FGxvs2M5gZxnmlvewIDAQAB
        """
    )!

    let publicKey4096Data = Data(base64Encoded: """
        MIICCgKCAgEAv+rKTWfCkZmUjQsppCM7u3DVz2bYaoFp/c5r4lwLJXvP9S99dAVMG5YHiJAHVLSMDIm0O5WTNR/1pvwPA57zal2Gss9q+a4imx+\
        f5pyC8e2vtrozS3hejcZyYSSdotJCSfGWaSh1/8CyIyrAoMfHLt4+YHH7U6N1h7nqIzt5thybBObsBkTiul5hMqxf02SEqxZpPfv0AKMKPontcx\
        uO1DRgQUkcPkljKSysurNwmET3Dl50NkuYhCsUe5mz5yu9GHT6HER+47helljRF4d1d4RTkzk1BnXy1ZbmsdTN9vewmYuAqACLAVdPiK4ejw46l\
        8aSOclazireRQ04ismklfP1wc3CJ532CZ4PKf0tfflOmhEAXyjF3VwQsj0yl/4S5JphoutWkq/hN1AVX6K3F9xEENm4dddaetFYWgQpjjth8UwM\
        /Svm7aflR9f+g/1xjxvaPAG+ir+NqIsFeVpk8OJ+ZKg1YMKmYIcyRptnn1XNdJz5724r1xge/oPzfFxYqGEeAmRhPaB5HgvS8ysF0YhtskJFGsB\
        6P3DxFm+1RgUg2IlwBa+8gGvkwZ5W0Hy1gyZo+BZVHG2G+un2nJd/t4L+io1bgBG3sE+vOmV98L6tTzlKdyroa9xi45QRiN0SzA0an0x1fdJzSk\
        h+FcVIQ0ELDJDgruI/mX4M/u3yazsCAwEAAQ==
        """
    )!

    // Generated by OpenSSL for `publicKey` (without leading 0x00).
    let expectedModulus2048Base64 = """
        iADzxMJ-l_NIVPbqz9eoBenUCCUiNNfZ37c6gUJwWEfJRyGchAe96m4GLr3pzj2A3Io4MSKf9dDWMak6qkR_XYljSjZBbXAhQan2sIB5qyPW7NJ\
        7XpJWHoaHdHwEN9Cj29zL-WtFk6lC1rPDmNPRTmRy0ct4EP4YJ49PMcoKJQKbog79ws1KdDzNGTVVkEgLB4VOlW8A164kaK8-xMUxTqySUtigLT\
        DUMqjQ_81SFgsNnMUqnxp87bKD77olYBia88r8V2YXEx1Jgl8t22gNNh6lkN8BDqlkb_Y2uS-c7vlYIfSH6WYkVsSPsrA-GLLRo_R07FGxvs2M5\
        gZxnmlvew
        """

    // Generated by OpenSSL for `publicKey 4096` (without leading 0x00).
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

    // Dummy data since wen don't (yet) implemnt any RSAPrivateKEyConvertible.
    let expectedPrivateExponentBase64 = "MHZ4Li4uS2d3"

    // Generated by OpenSSL for `publicKey` (without leading 0x00).
    let expectedModulusData = Data(bytes: [
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

    // Generated by OpenSSL for `publicKey`.
    let expectedExponentData = Data(bytes: [ 1, 0, 1 ])

    override func setUp() {
        super.setUp()
        setupKeyPair()
    }

    override func tearDown() {
        super.tearDown()
    }

    private func setupKeyPair() {
        if let path = Bundle(for: type(of: self)).path(forResource: "TestKey", ofType: "plist"), let keyDict = NSDictionary(contentsOfFile: path), let keyData = Data(base64Encoded: keyDict[privateKeyTag] as! String) {
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: 2048,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: false,
                    kSecAttrApplicationTag as String: privateKeyTag
                ]
            ]

            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
                print(error!)
                return
            }

            privateKey = key
            publicKey = SecKeyCopyPublicKey(key)
        }
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
