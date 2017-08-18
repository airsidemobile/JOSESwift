//
//  JOSE.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

protocol ClaimSet {
    var claims: [String: Any] { get }
}

protocol CompactSerializable {
    func serialize() -> String
}
