// swiftlint:disable force_unwrapping

import XCTest
@testable import JOSESwift

class JWSUnencodedPayloadTests: ECCryptoTestCase {

    let detachedPayload = Payload("...DETACHED_ASCII_PAYLOAD...".data(using: .ascii)!)

    let encodedPayload = "Li4uREVUQUNIRURfQVNDSUlfUEFZTE9BRC4uLg"

    var signer: Signer<SecKey> {
        Signer(signingAlgorithm: .ES256, key: allTestData.first!.privateKey)!
    }

    var verifier: Verifier {
        Verifier(verifyingAlgorithm: .ES256, key: allTestData.first!.publicKey)!
    }

    func testCompactSerializationWithUnencodedPayloadOptionHasDetachedPayload() throws {
        let header = try JWSHeader(parameters: [
            "b64": false, // unencoded payload
            "crit": ["b64"],
            "alg": "ES256"
        ])

        let compactSerialization = try JWS(header: header, payload: detachedPayload, signer: signer).compactSerializedString
        let components = compactSerialization.components(separatedBy: ".")

        XCTAssertEqual(components.count, 3)
        XCTAssertEqual(components[1], "") // payload is detached
    }

    func testCompactSerializationWithMissingCriticalHeaderHasEncodedPayload() throws {
        let header = try JWSHeader(parameters: [
            "b64": false, // unencoded payload
            "crit": [], // "b64" not set
            "alg": "ES256"
        ])

        let compactSerialization = try JWS(header: header, payload: detachedPayload, signer: signer).compactSerializedString
        let components = compactSerialization.components(separatedBy: ".")

        XCTAssertEqual(components[1], encodedPayload)
    }

    func testCompactSerializationWithExplicitlyEncodedPayloadHasEncodedPayload() throws {
        let header = try JWSHeader(parameters: [
            "b64": true, // explicitly encoded payload
            "crit": ["b64"],
            "alg": "ES256"
        ])

        let compactSerialization = try JWS(header: header, payload: detachedPayload, signer: signer).compactSerializedString
        let components = compactSerialization.components(separatedBy: ".")

        XCTAssertEqual(components[1], encodedPayload)
    }

    func testDeserializationAndValidityWithUnencodedDetachedPayload() throws {
        let header = try JWSHeader(parameters: [
            "b64": false, // unencoded payload
            "crit": ["b64"],
            "alg": "ES256"
        ])

        let compactSerialization = try JWS(header: header, payload: detachedPayload, signer: signer).compactSerializedString

        let decoded = try JWS(compactSerialization: compactSerialization, detachedPayload: detachedPayload)

        XCTAssertEqual(decoded.payload.data(), detachedPayload.data())
        XCTAssertTrue(decoded.isValid(for: verifier))
    }

    func testDeserializationAndValidityWithEncodedDetachedPayload() throws {
        let header = try JWSHeader(parameters: [
            "alg": "ES256"
        ])

        let compactSerialization = try JWS(header: header, payload: detachedPayload, signer: signer).compactSerializedString
        let components = compactSerialization.components(separatedBy: ".")
        let compactSerializationWithDetachedPayload = "\(components[0])..\(components[2])"

        let decoded = try JWS(compactSerialization: compactSerializationWithDetachedPayload, detachedPayload: detachedPayload)

        XCTAssertEqual(decoded.payload.data(), detachedPayload.data())
        XCTAssertTrue(decoded.isValid(for: verifier))
    }

    func testInitCompactSerializationWithPayloadAndDetachedPayloadIgnoresDetachedPayload() throws {
        let header = try JWSHeader(parameters: [
            "alg": "ES256"
        ])

        let payload = Payload("payload".data(using: .ascii)!)
        let compactSerializationWithPayload = try JWS(header: header, payload: payload, signer: signer).compactSerializedString

        let decoded = try JWS(compactSerialization: compactSerializationWithPayload, detachedPayload: detachedPayload)

        XCTAssertEqual(decoded.payload.data(), payload.data())
    }

}
