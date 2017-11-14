//
//  Data+Base64URL.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 22/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

extension Data {
    init?(base64URLEncoded: String) {
        var s = base64URLEncoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        let mod = s.count % 4
        switch mod {
        case 0: break
        case 2: s.append("==")
        case 3: s.append("=")
        default: return nil
        }
        
        self.init(base64Encoded: s)
    }
    
    init?(base64URLEncoded: Data) {
        guard let s = String(data: base64URLEncoded, encoding: .utf8) else {
            return nil
        }
        
        self.init(base64URLEncoded: s)
    }
    
    func base64URLEncodedString() -> String {
        let s = self.base64EncodedString()
        return s
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
    
    func base64URLEncodedData() -> Data {
        return self.base64URLEncodedString().data(using: .utf8)!
    }
}

extension Data: JOSEObjectComponent {
    public init(_ data: Data) {
        self = data
    }
    
    public func data() -> Data {
        return self
    }
}
