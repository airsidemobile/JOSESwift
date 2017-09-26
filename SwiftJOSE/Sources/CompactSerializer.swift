//
//  Serialization.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

// Data

protocol ExpressibleByData {
    init(_ data: Data)
    func data() -> Data
}

// Serialization

protocol CompactSerializable {
    func serialize(to serializer: inout CompactSerializerProtocol)
}

protocol CompactSerializerProtocol {
    var parts: [Data] { get }
    mutating func serialize<T: ExpressibleByData>(_ object: T)
}

struct CompactSerializer {
    func serialize<T: CompactSerializable>(_ object: T) -> String {
        var serializer: CompactSerializerProtocol = PrivateCompactSerializer()
        object.serialize(to: &serializer)
        let base64URLEncodings = serializer.parts.map() { part in
            return part.base64URLEncodedString()
        }
        return base64URLEncodings.joined(separator: ".")
    }
}

fileprivate struct PrivateCompactSerializer: CompactSerializerProtocol {
    var parts: [Data] = []
    
    mutating func serialize<T: ExpressibleByData>(_ object: T) {
        parts.append(object.data())
    }
}

// Deserialization

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
        let deserializer = PrivateCompactDeserializer(parts: parts)
        return T(from: deserializer)
    }
}

fileprivate struct PrivateCompactDeserializer: CompactDeserializerProtocol {
    let parts: [Data]
    
    func deserialize<T: ExpressibleByData>(_ type: T.Type, at index: Int) -> T {
        return T(parts[index])
    }
}
