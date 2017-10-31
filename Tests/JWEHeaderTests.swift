//
//  JWEHeaderTests.swift
//  Tests
//
//  Created by Carol Capek on 31.10.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import XCTest
@testable import SwiftJOSE

class JWEHeaderTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testInitWithParameters() {
        let parameters = ["alg": "RS512", "enc": "RS512"]
        let header = JWEHeader(parameters: parameters)
        
        XCTAssertEqual(header.parameters["enc"] as? String, parameters["enc"])
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameters, options: []))
    }
    
    func testInitWithData() {
        let data = try! JSONSerialization.data(withJSONObject: ["alg": "RS512", "enc": "RS512"], options: [])
        let header = JWEHeader(data)
        
        XCTAssertEqual(header.parameters["enc"] as? String, "RS512")
        XCTAssertEqual(header.data(), data)
    }
    
    func testInitWithAlgAndEnc() {
        let header = JWEHeader(algorithm: .rs512, encryptionAlgorithm: .rs512)
        
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: ["alg": "RS512", "enc": "RS512"], options: []))
        XCTAssertEqual(header.parameters["enc"] as? String, "RS512")
    }
    
}
