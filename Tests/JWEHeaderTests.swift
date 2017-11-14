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
    let parameterDict = ["alg": "RSA-OAEP", "enc": "A256GCM"]
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testInitWithParameters() {
        let header = JWEHeader(parameters: parameterDict)
        
        XCTAssertEqual(header.parameters["enc"] as? String, Algorithm.AESGCM256.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, Algorithm.RSAOAEP.rawValue)
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDict, options: []))
    }
    
    func testInitWithData() {
        let data = try! JSONSerialization.data(withJSONObject: parameterDict, options: [])
        let header = JWEHeader(data)
        
        XCTAssertEqual(header.parameters["enc"] as? String, Algorithm.AESGCM256.rawValue)
        XCTAssertEqual(header.parameters["alg"] as? String, Algorithm.RSAOAEP.rawValue)
        XCTAssertEqual(header.data(), data)
    }
    
    func testInitWithAlgAndEnc() {
        let header = JWEHeader(algorithm: .RSAOAEP, encryptionAlgorithm: .AESGCM256)
        
        XCTAssertEqual(header.data(), try! JSONSerialization.data(withJSONObject: parameterDict, options: []))
        XCTAssertEqual(header.parameters["alg"] as? String, Algorithm.RSAOAEP.rawValue)
        XCTAssertEqual(header.parameters["enc"] as? String, Algorithm.AESGCM256.rawValue)
    }
    
}
