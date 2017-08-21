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

public struct Header: ClaimSet, JSONEncodable, Base64URLEncodable {
    public var claims: [String: Any]
    
    public init(_ claims: [String: Any]) {
        self.claims = claims
    }
}

public struct Payload: ClaimSet, JSONEncodable, Base64URLEncodable {
    public var claims: [String: Any]
    
    public init(_ claims: [String: Any]) {
        self.claims = claims
    }
}

