//
//  Payload.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct Payload: ClaimSet, JSONEncodable {
    public var claims: [String: Any]
    
    public init(_ claims: [String: Any]) {
        self.claims = claims
    }
}
