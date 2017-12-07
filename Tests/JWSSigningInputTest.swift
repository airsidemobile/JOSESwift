//
//  JWSSigningInputTest.swift
//  Tests
//
//  Created by Daniel Egger on 07.12.17.
//

import XCTest
@testable import SwiftJOSE

class JWSSigningInputTest: XCTestCase {
    
    let header: DataConvertible = JWSHeader("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}".data(using: .utf8)!)!
    let payload: DataConvertible = Payload("{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}".data(using: .utf8)!)
    
    let expectedSigningInput: [UInt8] = [
        101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81,
        105, 76, 65, 48, 75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74,
        73, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51,
        77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67,
        74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84,
        107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100,
        72, 65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76,
        109, 78, 118, 98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73,
        106, 112, 48, 99, 110, 86, 108, 102, 81
    ]
    
    func testSigningInputComputation() {
        let signingInput: [UInt8] = Array([header, payload].asJOSESigningInput()!)
        XCTAssertEqual(signingInput, expectedSigningInput)
    }
    
}
