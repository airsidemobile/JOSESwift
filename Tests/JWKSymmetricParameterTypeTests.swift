//
//  JWKSymmetricParameterTypeTests.swift
//  Tests
//
//  Created by Daniel on 24.10.18.
//

import XCTest
@testable import JOSESwift

class JWKSymmetricParameterTypeTests: XCTestCase {

    let jwk = """
        {"kty": "oct", "alg": "A256CBC-HS512", "k": "GawgguFyGrWKav7AX4VKUg", "use": "enc", "kid": "12", "key_ops": ["s\
        ign", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"], "x5c": ["MIIDQjCCAiqgAwIBAgIGATz\
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
        XCTAssertNoThrow(try SymmetricKey(data: jwk))
    }

    func testDecodingStringParameters() {
        let key = try! SymmetricKey(data: jwk)

        XCTAssertEqual(key.keyType.rawValue, "oct")
        XCTAssertEqual(key.key, "GawgguFyGrWKav7AX4VKUg")
        XCTAssertEqual(key.keyUse, "enc")

        XCTAssertEqual(key.keyIdentifier ?? "", "12")
    }

    func testDecodingStringArrayParameterKeyOpsSubscript() {
        let key = try! SymmetricKey(data: jwk)

        let keyOperations = key["key_ops"] as? [String]

        XCTAssertNotNil(keyOperations)
        XCTAssertEqual(keyOperations!.count, 7)
        XCTAssertEqual(keyOperations![0], "sign")
        XCTAssertEqual(keyOperations![1], "encrypt")
        XCTAssertEqual(keyOperations![2], "decrypt")
        XCTAssertEqual(keyOperations![3], "wrapKey")
        XCTAssertEqual(keyOperations![4], "unwrapKey")
        XCTAssertEqual(keyOperations![5], "deriveKey")
        XCTAssertEqual(keyOperations![6], "deriveBits")
    }

    func testDecodingStringArrayParameterKeyOpsComputed() {
        let key = try! SymmetricKey(data: jwk)

        let keyOperations = key.keyOperations

        XCTAssertNotNil(keyOperations)
        XCTAssertEqual(keyOperations!.count, 7)
        XCTAssertEqual(keyOperations![0], "sign")
        XCTAssertEqual(keyOperations![1], "encrypt")
        XCTAssertEqual(keyOperations![2], "decrypt")
        XCTAssertEqual(keyOperations![3], "wrapKey")
        XCTAssertEqual(keyOperations![4], "unwrapKey")
        XCTAssertEqual(keyOperations![5], "deriveKey")
        XCTAssertEqual(keyOperations![6], "deriveBits")
    }

    func testDecodingStringArrayParameterCertificateChainSubscript() {
        let key = try! SymmetricKey(data: jwk)

        let certificateChain = key["x5c"] as? [String]

        XCTAssertNotNil(certificateChain)
        XCTAssertEqual(certificateChain!.count, 1)
        XCTAssertEqual(certificateChain![0].prefix(5), "MIIDQ")
        XCTAssertEqual(certificateChain![0].suffix(5), "OWA==")
    }

    func testDecodingStringArrayParameterCertificateChainComputed() {
        let key = try! SymmetricKey(data: jwk)

        let certificateChain = key.X509CertificateChain

        XCTAssertNotNil(certificateChain)
        XCTAssertEqual(certificateChain!.count, 1)
        XCTAssertEqual(certificateChain![0].prefix(5), "MIIDQ")
        XCTAssertEqual(certificateChain![0].suffix(5), "OWA==")
    }
}
