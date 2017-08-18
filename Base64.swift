//
//  Base64.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

protocol Base64URLEncodable {
    func base64URLEncodedString() -> String
}

extension Base64URLEncodable where Self: CustomStringConvertible {
    func base64URLEncodedString() -> String {
        return "Base64URL(\(self.description))"
    }
}

extension String: Base64URLEncodable { }
