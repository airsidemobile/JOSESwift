//
//  Data+Base64URLEncodeable.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

extension Data: Base64URLEncodeable {
    public func base64URLEncoded() -> String {
        return "Base64URL(\(String.init(data: self, encoding: .utf8)!))"
    }
}
