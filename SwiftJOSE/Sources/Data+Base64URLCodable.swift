//
//  Data+Base64URLCodable.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 22/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

extension Data: Base64URLCodable {
    init(base64URLEncoded: String) {
        // let base64Encoded = base64URLEncoded.replace("=", with: "") ...
        // self.init(base64Encoded: base64Encoded)!
        
        self = "{\"Dummy\":\"Base64URLDecodedData\"}".data(using: .utf8)!
    }
    
    func base64URLEncoded() -> String {
        return "Base64URL(\(String(data: self, encoding: .utf8)!))"
    }
}

