//
//  Base64URLEncodable.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public protocol Base64URLEncodable {
    func base64URLEncoded() -> String
}

extension Data: Base64URLEncodable {
    public func base64URLEncoded() -> String {
        return "Base64URL(\(String.init(data: self, encoding: .utf8)!))"
    }
}
