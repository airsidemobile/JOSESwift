//
//  DataExtensionTests.swift
//  Tests
//
//  Created by Carol Capek on 31.10.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import XCTest
@testable import SwiftJOSE

class DataExtensionTests: XCTestCase {
    
    let base64URLTestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIHdoZXJlIHRoZSBiYXNlNjQgcmVwcmVzZW50YXRpb24gY29udGFpbnMgYSA9IGFzIHBhZGRpbmc"
    let testString = "This is a test string where the base64 representation contains a = as padding"
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    //TODO: Naming???
    func testBase64URLStringInit() {
        let data = Data(base64URLEncoded: base64URLTestString)
        
        XCTAssertEqual(String(data: data, encoding: .utf8)!, testString)
    }
    
    func testBase64URLDataInit() {
        let data = Data(base64URLEncoded: base64URLTestString.data(using: .utf8)!)

        XCTAssertEqual(String(data: data, encoding: .utf8)!, testString)
    }
    
    func testDataToBase64URLString() {
        let data = testString.data(using: .utf8)!
        let base64URLString = data.base64URLEncodedString()

        XCTAssertEqual(base64URLString, base64URLTestString)
    }
    
    func testDataToBase64URLData() {
        let data = testString.data(using: .utf8)!
        let base64URLData = data.base64URLEncodedData()
        
        XCTAssertEqual(String(data: base64URLData, encoding: .utf8)!, base64URLTestString)
    }
    
}
