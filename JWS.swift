//
//  JWS.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct JWS: CompactSerializable {
    let header: Header
    let payload: Payload
    var signature: String?
    
    public init(header: Header, payload: Payload) {
        self.header = header
        self.payload = payload
    }
    
    public mutating func sign(using signer: Signer) {
        self.signature = signer.sign(self)
    }
    
    public func serialize() -> String {
        let header = self.header.jsonEncodedString().base64URLEncodedString()
        let payload = self.payload.jsonEncodedString().base64URLEncodedString()
        let signature = self.signature!.base64URLEncodedString()
        
        return "\(header).\(payload).\(signature)"
    }
}
