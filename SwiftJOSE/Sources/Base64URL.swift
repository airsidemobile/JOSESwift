//
//  Base64URL.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

typealias Base64URLCodable = Base64URLEncodable & Base64URLDecodable

protocol Base64URLDecodable {
    init(base64URLEncoded: String)
}

protocol Base64URLEncodable {
    func base64URLEncoded() -> String
}
