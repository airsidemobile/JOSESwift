//
//  JWSHeaderTests.swift
//  Tests
//
//  Created by Carol Capek on 30.10.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import XCTest
@testable import SwiftJOSE

class JWSHeaderTests: XCTestCase {
    let parameterDict = ["alg": "\(Algorithm.RS512.rawValue)"]
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testInitWithParameters() {
        let header = try! JWSHeader(parameters: parameterDict)

        XCTAssertEqual(header.parameters["alg"] as? String, parameterDict["alg"])
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDict, options: []))
    }
    
    func testInitWithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDict, options: [])
        let header = JWSHeader(data)!
        
        XCTAssertEqual(header.parameters["alg"] as? String, Algorithm.RS512.rawValue)
        XCTAssertEqual(header.data(), data)
    }
    
}
