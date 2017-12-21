//
//  JWS.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//

import Foundation

/// A JWS object consisting of a header, payload and signature. The three components of a JWS object
/// cannot be changed once the object is initialized.
public struct JWS {
    public let header: JWSHeader
    public let payload: Payload
    public let signature: Data

    /// The compact serialization of this JWS object.
    public var compactSerializedString: String {
        return JOSESerializer().serialize(compact: self)
    }
    
    // Force unwrapping is ok here, since `serialize` returns a string generated from data.
    // swiftlint:disable:next force_try
    public var compactSerializedData: Data {
        return JOSESerializer().serialize(compact: self).data(using: .utf8)!
    }

    /**
     Constructs a JWS object from a given header, payload, and signer.
     - Parameters:
         - header: A fully initialized `JWSHeader`.
         - payload: A fully initialized `JWSPayload`.
         - signer: The `Signer` used to compute the JWS signature from the header and payload.
    */
    public init?(header: JWSHeader, payload: Payload, signer: Signer) {
        self.header = header
        self.payload = payload

        if let signature = try? signer.sign(header: header, payload: payload) {
            self.signature = signature
        } else {
            return nil
        }
    }

    /**
     Constructs a JWS object from a given compact serialization.
     - parameters:
         - compactSerialization: A compact serialized JWS object as received e.g. from the server.
    */
    public init(compactSerialization: String) throws {
        self = try JOSEDeserializer().deserialize(JWS.self, fromCompactSerialization: compactSerialization)
    }
    
    public init(compactSerialization: Data) throws {
        guard let compactSerializationString = String(data: compactSerialization, encoding: .utf8) else {
            throw DeserializationError.wrongDataEncoding(data: compactSerialization)
        }

        self = try JOSEDeserializer().deserialize(JWS.self, fromCompactSerialization: compactSerializationString)
    }

    fileprivate init(header: JWSHeader, payload: Payload, signature: Data) {
        self.header = header
        self.payload = payload
        self.signature = signature
    }

    /**
     Verifies a JWS using a given public key.
     - parameters:
         - publicKey: The public key used to verify the JWS object's header and payload.
     - returns: `true` if the JWS object's signature could be verified against it's header and payload. `false` otherwise.
    */
    public func isValid(for publicKey: SecKey) -> Bool {
        guard let alg = header.algorithm else {
            return false
        }
        
        let verifier = Verifier(signingAlgorithm: alg, publicKey: publicKey)
        guard let result = try? verifier.verify(header: header, and: payload, against: signature) else {
            return false
        }

        return result
    }
}

extension JWS: CompactSerializable {
    public func serialize(to serializer: inout CompactSerializer) {
        serializer.serialize(header)
        serializer.serialize(payload)
        serializer.serialize(signature)
    }
}

extension JWS: CompactDeserializable {
    public static var componentCount: Int {
        return 3
    }

    public init(from deserializer: CompactDeserializer) throws {
        let header = try deserializer.deserialize(JWSHeader.self, at: ComponentCompactSerializedIndex.jwsHeaderIndex)
        let payload = try deserializer.deserialize(Payload.self, at: ComponentCompactSerializedIndex.jwsPayloadIndex)
        let signature = try deserializer.deserialize(Data.self, at: ComponentCompactSerializedIndex.jwsSignatureIndex)
        self.init(header: header, payload: payload, signature: signature)
    }
}
