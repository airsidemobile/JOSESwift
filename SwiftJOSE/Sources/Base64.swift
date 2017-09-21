//
//  Base64.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

struct Base64URL {
    static func encode(_ data: Data) -> String {
        return "Base64URL(\(String.init(data: data, encoding: .utf8)!))"
    }
}

public protocol Base64URLEncodeable {
    func base64URLEncoded() -> String
}
