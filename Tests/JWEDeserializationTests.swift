//
//  JWSDeserializationTests.swift
//  Tests
//
//  Created by Daniel Egger on 17.11.17.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import XCTest
@testable import SwiftJOSE

class JWEDeserializationTests: XCTestCase {
    
    let serialized = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"
    
    let expectedHeader = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}".data(using: .utf8)!
    let expectedEncryptedKey = Data(base64Encoded: "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx/etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d+StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam/lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i+vDxRfqNzo/tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ/ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg==")!
    let expectedInitializationVector = Data(base64Encoded: "48V1/ALb6US04U3b")!
    let expectedCiphertext = Data(base64Encoded: "5eym8TW/c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX/EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD/A")!
    let expectedAuthTag = Data(base64Encoded: "XFBoMYUZodetZdvTiFvSkQ==")!
    
    func testDeserialization() {
        let jwe = try? JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: serialized)
        
        XCTAssertNotNil(jwe)
        XCTAssertEqual(jwe!.header.data(), expectedHeader)
        XCTAssertEqual(jwe!.encryptedKey, expectedEncryptedKey)
        XCTAssertEqual(jwe!.initializationVector, expectedInitializationVector)
        XCTAssertEqual(jwe!.ciphertext, expectedCiphertext)
        XCTAssertEqual(jwe!.authenticationTag, expectedAuthTag)
    }
    
    func testDeserializationWithTooManyComponentsInSerialization() {
        let wrongSerialization = serialized + "." + serialized
        
        do {
            _ = try JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: wrongSerialization)
        } catch DeserializationError.invalidCompactSerializationComponentCount(let count) {
            XCTAssertEqual(count, 10)
            return
        } catch {
            XCTFail()
        }
        
        XCTFail()
    }
    
    func testDeserializationWithInvalidBase64URLInSerialization() {
        // Make the base64url encoding of the authentication tag invalid in length.
        let wrongSerialization = serialized + "XXX"
        
        do {
            _ = try JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: wrongSerialization)
        } catch DeserializationError.componentNotValidBase64URL(let component) {
            XCTAssertEqual(component, "XFBoMYUZodetZdvTiFvSkQXXX")
            return
        } catch {
            XCTFail()
        }
        
        XCTFail()
    }
    
    func testDeserializationWithNonJSONHeaderInSerialization() {
        // Set header to: `{"alg":"RSA-OAEP",` which is not valid JSON.
        let wrongSerialization = serialized.replacingOccurrences(of: "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ", with: "e2FsZzpSU0EtT0FFUCwK")
        
        do {
            _ = try JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: wrongSerialization)
        } catch DeserializationError.componentCouldNotBeInitializedFromData(let data) {
            XCTAssertEqual(data, Data(base64URLEncoded:"e2FsZzpSU0EtT0FFUCwK")!)
            return
        } catch {
            XCTFail()
        }
        
        XCTFail()
    }
    
    func testDeserializationWithNonStringAnyHeaderInSerialization() {
        // Set header to: `{"typ":"JWE",1:"RSA-OAEP"}` which is not a valid `[String: Any]` dictionary.
        let wrongSerialization = serialized.replacingOccurrences(of: "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ", with: "eyJ0eXAiOiJKV0UiLDE6IlJTQS1PQUVQIn0")
        
        do {
            _ = try JOSEDeserializer().deserialize(JWE.self, fromCompactSerialization: wrongSerialization)
        } catch DeserializationError.componentCouldNotBeInitializedFromData(let data) {
            XCTAssertEqual(data, Data(base64URLEncoded:"eyJ0eXAiOiJKV0UiLDE6IlJTQS1PQUVQIn0")!)
            return
        } catch {
            XCTFail()
        }
        
        XCTFail()
    }
}
