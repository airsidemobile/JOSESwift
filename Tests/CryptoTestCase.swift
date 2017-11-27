//
//  CryptoTestCase.swift
//  Tests
//
//  Created by Carol Capek on 02.11.17.
//

import XCTest

class CryptoTestCase: XCTestCase {
    let message = "The true sign of intelligence is not knowledge but imagination."
    let privateKeyTag = "com.airsidemobile.SwiftJOSE.testPrivateKey"
    var privateKey: SecKey? = nil
    var publicKey: SecKey? = nil
    
    let compactSerializedJWSConst = "eyJhbGciOiJSUzUxMiJ9.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.dar4uQfhg7HpAXDrFJEP3T6cPePUIstu3tCLiz-HBEx1yAQXxLweQrKOYvIWOlt_HfxjjhxfGDoSXjnQMVHZTJaAYFNtK382pfOKpJAxE6UvkhLtvS-A6BKLWMS_aUVgqizOIXH0IeuVz1COpSLlsQ5KICUaqsxYyPfD28vbbQ9IfJ4RyJmSqEEx-M8BY2r4v_HHL-kyvjqGbSoF7o9Z6Cg1CetPJ5OHPBMXZa_Aj3LkNWn1GSw5B4WQueb8E0uJVAzLSNbxA-ZNowlOgDtKHOEkwbZu6zj7WvLEm8xovgmAha_y7HssoXnH26Nu-8RMUYw-LXUJz6Fny1F_xcv_TA"
    
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
