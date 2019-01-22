//
//  JWKECParameterTypeTests.swift
//  Tests
//
//  Created by Daniel on 24.10.18.
//

import XCTest
@testable import JOSESwift

class JWKECParameterTypeTests: XCTestCase {

    let jwk = """
        {"kty": "EC", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuh\
        p7x8PxltmWWlbbM4IFyM","use": "enc", "kid" :"1", "key_ops": ["sign", "verify"], "x5c": ["MIIDQjCCAiqgAwIBAgIGATz\
        /FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW\
        50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTM\
        QswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVs\
        bDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRi\
        j66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmF\
        gHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEv\
        qqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXN\
        swb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLE\
        aS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2\
        qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]}
        """.data(using: .utf8)!

    func testDecodingStringAndStringArrayParametersDoesNotThrow() {
        XCTAssertNoThrow(try ECPublicKey(data: jwk))
    }

    func testDecodingStringParameters() {
        let key = try! ECPublicKey(data: jwk)

        XCTAssertEqual(key.keyType.rawValue, "EC")
        XCTAssertEqual(key.x.prefix(5), "MKBCT")
        XCTAssertEqual(key.x.suffix(5), "qv7D4")
        XCTAssertEqual(key.y.prefix(5), "4Etl6")
        XCTAssertEqual(key.y.suffix(5), "4IFyM")
        XCTAssertEqual(key.keyUse, "enc")

        XCTAssertEqual(key.crv, ECCurveType.P256)
        XCTAssertEqual(key.keyIdentifier ?? "", "1")
    }

    func testDecodingStringArrayParameterKeyOpsSubscript() {
        let key = try! ECPublicKey(data: jwk)

        let keyOperations = key["key_ops"] as? [String]

        XCTAssertNotNil(keyOperations)
        XCTAssertEqual(keyOperations!.count, 2)
        XCTAssertEqual(keyOperations![0], "sign")
        XCTAssertEqual(keyOperations![1], "verify")
    }

    func testDecodingStringArrayParameterKeyOpsComputed() {
        let key = try! ECPublicKey(data: jwk)

        let keyOperations = key.keyOperations

        XCTAssertNotNil(keyOperations)
        XCTAssertEqual(keyOperations!.count, 2)
        XCTAssertEqual(keyOperations![0], "sign")
        XCTAssertEqual(keyOperations![1], "verify")
    }

    func testDecodingStringArrayParameterCertificateChainSubscript() {
        let key = try! ECPublicKey(data: jwk)

        let certificateChain = key["x5c"] as? [String]

        XCTAssertNotNil(certificateChain)
        XCTAssertEqual(certificateChain!.count, 1)
        XCTAssertEqual(certificateChain![0].prefix(5), "MIIDQ")
        XCTAssertEqual(certificateChain![0].suffix(5), "OWA==")
    }

    func testDecodingStringArrayParameterCertificateChainComputed() {
        let key = try! ECPublicKey(data: jwk)

        let certificateChain = key.X509CertificateChain

        XCTAssertNotNil(certificateChain)
        XCTAssertEqual(certificateChain!.count, 1)
        XCTAssertEqual(certificateChain![0].prefix(5), "MIIDQ")
        XCTAssertEqual(certificateChain![0].suffix(5), "OWA==")
    }
}
