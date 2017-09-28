//
//  JWS.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct JWS {
    let header: JWSHeader
    let payload: Payload
    let signature: Signature
    
    public var compactSerialized: String {
        return Serializer().compact(self)
    }
    
    public init(header: JWSHeader, payload: Payload, signer: Signer) {
        self.header = header
        self.payload = payload
        self.signature = Signature(from: signer, using: header, and: payload)!
    }
    
    public init(compactSerialization: String) {
        self = Deserializer().deserialize(JWS.self, fromCompactSerialization: compactSerialization)
    }
    
    fileprivate init(header: JWSHeader, payload: Payload, signature: Signature) {
        self.header = header
        self.payload = payload
        self.signature = signature
    }
    
    public func validates(with verifier: Verifier) -> Bool {
        return signature.validate(with: verifier, against: header, and: payload)
    }
}

extension JWS: CompactSerializable {
    func serialize(to serializer: inout CompactSerializer) {
        serializer.serialize(header)
        serializer.serialize(payload)
        serializer.serialize(signature)
    }
}

extension JWS: CompactDeserializable {
    init(from deserializer: CompactDeserializer) {
        let header = JWSHeader(from: deserializer)
        let payload = Payload(from: deserializer)
        let signature = Signature(from: deserializer)
        self.init(header: header, payload: payload, signature: signature)
    }
}

extension JWS: CustomStringConvertible {
    public var description: String {
        let header = self.header.parameters.description
        let payload = String(data: self.payload.data(), encoding: .utf8)!
        let signature = String(data: self.signature.data(), encoding: .utf8)!
        return "\(header) . \(payload) . \(signature)"
    }
}
