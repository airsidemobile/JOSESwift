//
//  Serialization.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

struct CompactSerializer {
    static func serialize(_ parts: [Base64URLEncodeable]) -> String {
        let base64URLEncodings = parts.map() { part in
            return part.base64URLEncoded()
        }
        return base64URLEncodings.joined(separator: ".")
    }
}

public protocol CompactSerializable {
    func compactSerialization() -> String
}
