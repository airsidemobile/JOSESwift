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
}

extension Payload: ExpressibleByData {
    func data() -> Data {
        return payload
    }
}

extension Payload: CompactDeserializable {
    init(from deserializer: CompactDeserializerProtocol) {
        self = deserializer.deserialize(Payload.self, at: 1)
    }
}

