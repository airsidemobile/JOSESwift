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
        
        let signatureInput = "\(header.base64URLEncoded()).\(payload.base64URLEncoded())".data(using: .utf8)!
        self.signature = signer.sign(signatureInput)
    }
    
    public func serialized() -> String {
        return CompactSerializer.serialize([header, payload, signature])
    }
}
