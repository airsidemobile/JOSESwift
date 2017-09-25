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
        self = "{\"Dummy\":\"Base64URLDecodedData\"}".data(using: .utf8)!
    }
    
    func base64URLEncoded() -> String {
        return "Base64URL(\(String(data: self, encoding: .utf8)!))"
    }
}
