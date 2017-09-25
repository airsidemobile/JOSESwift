//
//  JWS.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct JWS {
    let header: Header
    let payload: Payload
    let signature: Signature
    
    public init(header: Header, payload: Payload, signer: Signer) {
        self.header = header
        self.payload = payload

        let signatureInput = CompactSerializer().serialize([header, payload]).data(using: .utf8)!
        self.signature = Signature(signer.sign(signatureInput))
    }
    
    fileprivate init(header: Header, payload: Payload, signature: Signature) {
        self.header = header
        self.payload = payload
        self.signature = signature
    }
}

extension JWS: CompactSerializable {
    public func compactSerialization() -> String {
        return CompactSerializer().serialize([header, payload, signature])
    }
}

extension JWS: CompactDeserializable {
    init(from deserializer: CompactDeserializerProtocol) {
        let header = Header(from: deserializer)
        let payload = Payload(from: deserializer)
        let signature = Signature(from: deserializer)
        self.init(header: header, payload: payload, signature: signature)
    }
}
