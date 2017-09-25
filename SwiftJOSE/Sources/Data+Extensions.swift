//
//  Data+Base64URLCodable.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 22/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

extension Data {
    init(base64URLEncoded: String) {
        self = Data.init(base64Encoded: base64URLEncoded)! // Attention: base64 != base64URL
    }
    
    init(base64URLEncoded: Data) {
        self = Data.init(base64Encoded: base64URLEncoded)! // Attention: base64 != base64URL
    }
    
    func base64URLEncodedString() -> String {
        return "Base64URL(\(String(data: self, encoding: .utf8)!))"
    }
    
    func base64URLEncodedData() -> Data {
        return base64EncodedString().data(using: .utf8)!
    }
}
