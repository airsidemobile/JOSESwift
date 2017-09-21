//
//  Payload.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct Payload {
    let data: Data?
    let dict: [String: Any]?
    
    public init(_ data: Data) {
        self.data = data
        self.dict = nil
    }
    
    public init(_ dict: [String: Any]) {
        self.data = nil
        self.dict = dict
    }
}

extension Payload: Base64URLEncodable {
    func base64URLEncodedString() -> String {
        if data == nil, let dict = dict {
            return try! JSONSerialization.data(withJSONObject: dict, options: []).base64URLEncodedString()
        }
        
        return data!.base64URLEncodedString()
    }
}
