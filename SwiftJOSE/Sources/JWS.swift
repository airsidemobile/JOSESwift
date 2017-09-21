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
    let signature: Data
    
    public init(header: Header, payload: Payload, signer: Signer) {
        self.header = header
        self.payload = payload
        
        let serializer = CompactSerializer()
        let signatureInput = serializer.serialize([header, payload]).data(using: .utf8)!
        self.signature = signer.sign(signatureInput)
    }
}

extension JWS: CompactSerializable {
    public func compactSerialization() -> String {
        let serializer = CompactSerializer()
        return serializer.serialize([header, payload, signature])
    }
}
