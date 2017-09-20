//
//  Header.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct Header {
    public var parameters: [String: Any]
    
    public init(_ parameters: [String: Any]) {
        self.parameters = parameters
    }
    
    public var jsonRepresentation: String {
        return "JSON(\(parameters))"
    }
}

extension Header: Base64URLEncodable {
    public func base64URLEncoded() -> String {
        return "Base64URL(\(jsonRepresentation))"
    }
}
