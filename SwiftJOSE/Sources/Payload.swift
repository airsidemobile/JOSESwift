//
//  Payload.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct Payload {
    let payload: Any
    
    public init(_ data: Data) {
        self.payload = data
    }
    
    public init(_ dict: [String: Any]) {
        self.payload = dict
    }
    
    var jsonRepresentation: String? {
        return "JSON?(\(payload))"
    }
}

extension Payload: Base64URLEncodable {
    public func base64URLEncoded() -> String {
        if let json = jsonRepresentation {
            return "Base64URL(\(json))"
        }
        
        return "Base64URL(\(payload))"
    }
}
