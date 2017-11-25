//
//  RSASignerTests.swift
//  Tests
//
//  Created by Carol Capek on 02.11.17.
//

import XCTest
@testable import SwiftJOSE

class RSASignerTests: CryptoTestCase {
    let signatureBase64URL = "Zs9rmMw-za1uXpUS2VIOcEHaMuzQl6fBCi_40kRVIE0GUruWSvpHro1oXhGwf7HqKPLx_LM8bLPCORWi9OWU4swZHY8p-GR5rhLLs2XkdIvI5kdbikr7pZOsC9NaxJKMWAntKbTZY6exkoU8vM6xL9MQtH8QFLXTjI-ZvAXbp2Ws9CnIcvOPFqAupuUKADFRpSlODlsXy71CJ3iQeBaPfHvLk61jdW6hgHYj-0WYmrFhiF1dI9MZf9J3ApdKFsW0WFuxa8Y47HlCirEOb3lz7vm8o9lNBTnt0dpWOZMTU6lHuTBgiXvyENzJoKJymVsUbMmy-2LNejmVpPt1Pm3zrA"
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testSigning() {
        guard privateKey != nil else {
            XCTFail()
            return
        }
    
        let signer = RSASigner(key: privateKey!)
        let signature = try! signer.sign(message.data(using: .utf8)!, using: .RS512)
        
        XCTAssertEqual(signature.base64URLEncodedString(), signatureBase64URL)
    }
}
