//
//  Data+Base64URL.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 22/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

extension Data {
    init(base64URLEncoded: String) {
        // Convert to base64 with the restrictions defined in RFC-7515
        self = Data(base64Encoded: base64URLEncoded)!
    }
    
    init(base64URLEncoded: Data) {
        // Convert to base64 with the restrictions defined in RFC-7515
        self = Data(base64Encoded: base64URLEncoded)!
    }
    
    func base64URLEncodedString() -> String {
        return self.base64EncodedString() // NOTE: base64 != base64URL
    }
    
    func base64URLEncodedData() -> Data {
        return base64EncodedData() // NOTE: base64 != base64URL
    }
}

extension Data: JOSEObjectComponent {
    public init(from data: Data) {
        self = data
    }
    
    public func data() -> Data {
        return self
    }
}
