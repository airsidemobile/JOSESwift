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
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testInitFromParameters() {
        let parameters = ["alg": "RS512"]
        let header = JWSHeader(parameters: parameters)

        XCTAssertEqual(header.parameters["alg"] as? String, parameters["alg"])
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameters, options: []))
    }
    
    func testInitFromData() {
        let data = try! JSONSerialization.data(withJSONObject: ["alg": "RS512"], options: [])
        let header = JWSHeader(data)
        
        XCTAssertEqual(header.parameters["alg"] as! String, "RS512")
        XCTAssertEqual(header.data(), data)
    }
    
    }
    
}
