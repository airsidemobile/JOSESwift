//
//  JWKParameterTypeTests.swift
//  Tests
//
//  Created by Daniel on 24.10.18.
//

import XCTest
@testable import JOSESwift

class JWKParameterTypeTests: XCTestCase {

    let jwk = """
        { "kty": "RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJ\
        ECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8\
        KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls\
        1jF44-csFCur-kEgU8awapJzKnqDKgw", "e": "AQAB", "alg": "RS256", "key_ops": ["sign", "verify"], "x5c": ["MIIDQjCC\
        AiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQ\
        KExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCz\
        AJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5Cc\
        mlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6a\
        mFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jI\
        QRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDW\
        m1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlc\
        I0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3\
        PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5\
        rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA\
        =="], "kid": "2011-04-29", "use":"sig"}
        """.data(using: .utf8)!

    func testDecodingStringAndStringArrayParametersDoesNotThrow() {
        XCTAssertNoThrow(try RSAPublicKey(data: jwk))
    }

    func testDecodingStringParameters() {
        let key = try! RSAPublicKey(data: jwk)

        XCTAssertEqual(key.keyType.rawValue, "RSA")
        XCTAssertEqual(key.modulus.prefix(5), "0vx7a")
        XCTAssertEqual(key.modulus.suffix(5), "qDKgw")
        XCTAssertEqual(key.exponent, "AQAB")
        XCTAssertEqual(key.keyUse, "sig")

        XCTAssertEqual(key.algorithm ?? "", "RS256")
        XCTAssertEqual(key.keyIdentifier ?? "", "2011-04-29")
    }

    func testDecodingStringArrayParameterKeyOpsSubscript() {
        let key = try! RSAPublicKey(data: jwk)

        let keyOperations = key["key_ops"] as? [String]

        XCTAssertNotNil(keyOperations)
        XCTAssertEqual(keyOperations!.count, 2)
        XCTAssertEqual(keyOperations![0], "sign")
        XCTAssertEqual(keyOperations![1], "verify")
    }

    func testDecodingStringArrayParameterKeyOpsComputed() {
        let key = try! RSAPublicKey(data: jwk)

        let keyOperations = key.keyOperations

        XCTAssertNotNil(keyOperations)
        XCTAssertEqual(keyOperations!.count, 2)
        XCTAssertEqual(keyOperations![0], "sign")
        XCTAssertEqual(keyOperations![1], "verify")
    }

    func testDecodingStringArrayParameterCertificateChainSubscript() {
        let key = try! RSAPublicKey(data: jwk)

        let certificateChain = key["x5c"] as? [String]

        XCTAssertNotNil(certificateChain)
        XCTAssertEqual(certificateChain!.count, 1)
        XCTAssertEqual(certificateChain![0].prefix(5), "MIIDQ")
        XCTAssertEqual(certificateChain![0].suffix(5), "OWA==")
    }

    func testDecodingStringArrayParameterCertificateChainComputed() {
        let key = try! RSAPublicKey(data: jwk)

        let certificateChain = key.X509CertificateChain

        XCTAssertNotNil(certificateChain)
        XCTAssertEqual(certificateChain!.count, 1)
        XCTAssertEqual(certificateChain![0].prefix(5), "MIIDQ")
        XCTAssertEqual(certificateChain![0].suffix(5), "OWA==")
    }
}
