//
//  Serialization.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public protocol CompactSerializable {
    func compactSerialization() -> String
}

struct CompactSerializer {
    func serialize(_ parts: [ExpressibleByData]) -> String {
        let base64URLEncodings = parts.map() { part in
            return part.data().base64URLEncodedString()
        }
        return base64URLEncodings.joined(separator: ".")
    }
}

// Deserialization

protocol ExpressibleByData {
    init(_ data: Data)
    func data() -> Data
}

protocol CompactDeserializable {
    init(from deserializer: CompactDeserializerProtocol)
}

protocol CompactDeserializerProtocol {
    func deserialize<T: ExpressibleByData>(_ type: T.Type, at index: Int) -> T
}

struct CompactDeserializer {
    func deserialize<T: CompactDeserializable>(_ type: T.Type, from compactSerialization: String) -> T {
        let parts = compactSerialization.components(separatedBy: ".").map() { part in
            return Data.init(base64URLEncoded: part)
        }
        let deserializer = _CompactDeserializer(parts: parts)
        return T(from: deserializer)
    }
}

struct _CompactDeserializer: CompactDeserializerProtocol {
    let parts: [Data]
    
    func deserialize<T: ExpressibleByData>(_ type: T.Type, at index: Int) -> T {
        return T(parts[index])
    }
}
