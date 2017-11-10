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
    let parameterDict = ["alg": "RS512", "enc": "RS512"]
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testInitWithParameters() {
        let header = try! JWEHeader(parameters: parameterDict)
        
        XCTAssertEqual(header.parameters["enc"] as? String, Algorithm.RS512.rawValue)
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDict, options: []))
    }
    
    func testInitWithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDict, options: [])
        let header = JWEHeader(data)
        
        XCTAssertEqual(header.parameters["enc"] as? String, Algorithm.RS512.rawValue)
        XCTAssertEqual(header.data(), data)
    }
    
    func testInitWithAlgAndEnc() {
        let header = JWEHeader(algorithm: .RS512, encryptionAlgorithm: .RS512)
        
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDict, options: []))
        XCTAssertEqual(header.parameters["enc"] as? String, Algorithm.RS512.rawValue)
    }
    
}
