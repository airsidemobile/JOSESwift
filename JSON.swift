//
//  JSONConvertbile.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

protocol JSONEncodable {
    func jsonEncodedString() -> String
}

extension JSONEncodable where Self: ClaimSet {
    func jsonEncodedString() -> String {
        return "JSON(\(claims))"
    }
}
