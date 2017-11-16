//
//  JOSEDeserializer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 26/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

enum DeserializationError: Error {
    case invalidCompactSerializationLength
    case componentNotValidBase64URL(component: String)
}

public protocol CompactDeserializable {
    static var count: Int { get }
    init(from deserializer: CompactDeserializer)
}

public protocol CompactDeserializer {
    func deserialize<T: JOSEObjectComponent>(_ type: T.Type, at index: Int) -> T
}

public struct JOSEDeserializer {
    public init() { }
    
    public func deserialize<T: CompactDeserializable>(_ type: T.Type, fromCompactSerialization compactSerialization: String) throws -> T {
        let encodedComponents = compactSerialization.components(separatedBy: ".")
        
        guard encodedComponents.count == type.count else {
            throw DeserializationError.invalidCompactSerializationLength
        }
        
        let decodedComponents = try encodedComponents.map { (component: String) throws -> Data in
            guard let data = Data(base64URLEncoded: component) else {
                throw DeserializationError.componentNotValidBase64URL(component: component)
            }
            return data
        }
        
        let deserializer = _CompactDeserializer(components: decodedComponents)
        
        return T(from: deserializer)
    }
}

fileprivate struct _CompactDeserializer: CompactDeserializer {
    let components: [Data]
    
    func deserialize<T: JOSEObjectComponent>(_ type: T.Type, at index: Int) -> T {
        return T(components[index])
    }
}
