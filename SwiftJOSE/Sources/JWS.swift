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
    
    public init(header: JWSHeader, payload: Payload, signer: Signer) {
        self.header = header
        self.payload = payload

        let signatureInput = "\(header.data().base64URLEncodedString()).\(payload.data().base64URLEncodedString())"
        self.signature = Signature(signer.sign(signatureInput.data(using: .utf8)!))
    }
    
    fileprivate init(header: JWSHeader, payload: Payload, signature: Signature) {
        self.header = header
        self.payload = payload
        self.signature = signature
    }
    
    public func validates(against verifier: Verifier) -> Bool {
        let signatureInput = "\(header.data().base64URLEncodedString()).\(payload.data().base64URLEncodedString())".data(using: .utf8)!
        return verifier.verify(signature.data(), against: signatureInput)
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
