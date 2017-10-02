//
//  JWSPayload.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 02/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct JWSPayload: Payload {
    let data: Data
    
    public init(_ data: Data) {
        self.data = data
    }
}

extension JWSPayload: CompactDeserializable {
    public init(from deserializer: CompactDeserializer) {
        self = deserializer.deserialize(JWSPayload.self, at: 1)
    }
}
