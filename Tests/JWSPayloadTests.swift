//
//  JWSPayloadTests.swift
//  Tests
//
//  Created by Carol Capek on 31.10.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import XCTest
@testable import SwiftJOSE

class JWSPayloadTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testDeserializationFromCompactSerialization() {
        let compactSerializedJWS = "eyJhbGciOiJSUzUxMiJ9.SGVsbG8gd29ybGQh.UlM1MTIoZXlKaGJHY2lPaUpTVXpVeE1pSjkuU0dWc2JHOGdkMjl5YkdRaCk"
        
        let jwsPayload = JOSEDeserializer().deserialize(JWSPayload.self, fromCompactSerialization: compactSerializedJWS)
        XCTAssertEqual(String(data: jwsPayload.data(), encoding: .utf8), "Hello world!")
    }
}
