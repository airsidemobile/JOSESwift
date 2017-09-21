//
//  Header.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct Header {
    let parameters: [String: Any]
    
    public init(_ parameters: [String: Any]) {
        self.parameters = parameters
    }
}

extension Header: Base64URLEncodeable {
    public func base64URLEncoded() -> String {
        let data = try! JSONSerialization.data(withJSONObject: parameters, options: [])
        return "Base64URL(\(String(data: data, encoding: .utf8)!))"
    }
}
