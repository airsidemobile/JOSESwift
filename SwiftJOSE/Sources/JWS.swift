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
    let header: JWSHeader
    let payload: Payload
    let signature: Signature
    
    /// The compact serialization of this JWS object.
    public var compactSerialized: String {
        return JOSESerializer().serialize(compact: self)
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
        
        if let signature = Signature(from: signer, using: header, and: payload) {
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
    
    fileprivate init(header: JWSHeader, payload: Payload, signature: Signature) {
        self.header = header
        self.payload = payload
        self.signature = signature
    }
    
    /**
     Validates a JWS using a given verifier.
     - parameters:
         - verifier: The `Verifier` used to verify the JWS object's header and payload.
     - returns: `true` if the JWS object's signature could be verified against it's header and payload. `false` otherwise.
    */
    public func validates(against verifier: Verifier) -> Bool {
        return signature.validate(with: verifier, against: header, and: payload)
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
        let signature = try deserializer.deserialize(Signature.self, at: ComponentCompactSerializedIndex.jwsSignatureIndex)
        self.init(header: header, payload: payload, signature: signature)
    }
}
