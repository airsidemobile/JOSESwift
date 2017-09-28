//
//  Payload.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 20/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct Payload {
    fileprivate let payload: Data

    public init(_ payload: Data) {
        self.payload = payload
    }
    
    public init(_ message: String) {
        self.payload = message.data(using: .utf8)!
    }
}

extension Payload: JOSEObjectComponent {
    init(from data: Data) {
        self.payload = data
    }
    
    func data() -> Data {
        return payload
    }
}

extension Payload: CompactDeserializable {
    init(from deserializer: CompactDeserializer) {
        self = deserializer.deserialize(Payload.self, at: 1)
    }
}

