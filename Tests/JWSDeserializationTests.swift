//
//  JWSDeserializationTests.swift
//  Tests
//
//  Created by Daniel Egger on 17.11.17.
//

import XCTest
@testable import SwiftJOSE

class JWSDeserializationTests: XCTestCase {

    let serialized = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.x2cs4hRCGTt26GSwzk9DHqnt1Qk6jN-s9OEB7EBTAQI"

    let expectedHeader = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}".data(using: .utf8)!
    let expectedPayload = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}".data(using: .utf8)!
    let expectedSignature = Data(base64Encoded: "x2cs4hRCGTt26GSwzk9DHqnt1Qk6jN+s9OEB7EBTAQI=")!

    func testDeserialization() {
        let jws = try? JOSEDeserializer().deserialize(JWS.self, fromCompactSerialization: serialized)

        XCTAssertNotNil(jws)
        XCTAssertEqual(jws!.header.data(), expectedHeader)
        XCTAssertEqual(jws!.payload.data(), expectedPayload)
        XCTAssertEqual(jws!.signature.data(), expectedSignature)
    }

    func testDeserializationWithTooManyComponentsInSerialization() {
        let wrongSerialization = serialized + "." + serialized

        do {
            _ = try JOSEDeserializer().deserialize(JWS.self, fromCompactSerialization: wrongSerialization)
        } catch DeserializationError.invalidCompactSerializationComponentCount(let count) {
            XCTAssertEqual(count, 6)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testDeserializationWithInvalidBase64URLInSerialization() {
        // Make the base64url encoding of the signature invalid in length.
        let wrongSerialization = serialized + "XX"

        do {
            _ = try JOSEDeserializer().deserialize(JWS.self, fromCompactSerialization: wrongSerialization)
        } catch DeserializationError.componentNotValidBase64URL(let component) {
            XCTAssertEqual(component, "x2cs4hRCGTt26GSwzk9DHqnt1Qk6jN-s9OEB7EBTAQIXX")
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testDeserializationWithNonJSONHeaderInSerialization() {
        // Set header to: `{"typ":"JWT"` which is not valid JSON.
        let wrongSerialization = serialized.replacingOccurrences(of: "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", with: "eyJ0eXAiOiJKV1Qi")

        do {
            _ = try JOSEDeserializer().deserialize(JWS.self, fromCompactSerialization: wrongSerialization)
        } catch DeserializationError.componentCouldNotBeInitializedFromData(let data) {
            XCTAssertEqual(data, Data(base64URLEncoded:"eyJ0eXAiOiJKV1Qi")!)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

    func testDeserializationWithNonStringAnyHeaderInSerialization() {
        // Set header to: `{"typ":"JWS",1:"HS256"}` which is not a valid `[String: Any]` dictionary.
        let wrongSerialization = serialized.replacingOccurrences(of: "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", with: "eyJ0eXAiOiJKV1QiLDE6IkhTMjU2In0")

        do {
            _ = try JOSEDeserializer().deserialize(JWS.self, fromCompactSerialization: wrongSerialization)
        } catch DeserializationError.componentCouldNotBeInitializedFromData(let data) {
            XCTAssertEqual(data, Data(base64URLEncoded:"eyJ0eXAiOiJKV1QiLDE6IkhTMjU2In0")!)
            return
        } catch {
            XCTFail()
        }

        XCTFail()
    }

}
