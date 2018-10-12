//
//  JWKx5cTests.swift
//  Tests
//
//  Created by Xaver Lohmüller on 12.10.18.
//

import XCTest
@testable import JOSESwift

class JWKx5cTests: XCTestCase {
    func testBuildingJWKSetShouldNotFailIfCertificatesArePresent() {
        XCTAssertNoThrow(try JWKSet(data: json))
    }
}

private let json = """
{
    "keys": [{
        "kty": "RSA",
        "e": "AQAB",
        "use": "enc",
        "x5t": "eGydA5CgawshHa8ULkMyn5gl9eI",
        "kid": "kid-12345",
        "x5c": ["Y2VydGlmaWNhdGUxMjM0NWRhdGEx"],
        "n": "4r7_nnmRn9hppkfxt8p"
    }, {
        "kty": "RSA",
        "e": "AQAB",
        "use": "sig",
        "x5t": "gpYbURn6jaHwNX9xhE2MGCIXPd0",
        "kid": "kid-12346",
        "x5c": ["Y2VydGlmaWNhdGUxMjM0NWRhdGEy"],
        "n": "rTZj4tESZaNMpwsj"
    }]
}
""".data(using: .utf8)!
