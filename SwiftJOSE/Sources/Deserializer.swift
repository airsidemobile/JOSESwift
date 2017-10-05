//
//  JOSEDeserializer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 26/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public protocol CompactDeserializable {
    init(from deserializer: CompactDeserializer)
}

public protocol CompactDeserializer {
    func deserialize<T: JOSEObjectComponent>(_ type: T.Type, at index: Int) -> T
}

public struct JOSEDeserializer {
    public init() { }
    public func deserialize<T: CompactDeserializable>(_ type: T.Type, fromCompactSerialization compactSerialization: String) -> T {
        let encodedComponents = compactSerialization.components(separatedBy: ".")
        let decodedComponents = encodedComponents.map { component in Data(base64URLEncoded: component) }
        let deserializer = _CompactDeserializer(components: decodedComponents)
        return T(from: deserializer)
    }
}

fileprivate struct _CompactDeserializer: CompactDeserializer {
    let components: [Data]
    
    func deserialize<T: JOSEObjectComponent>(_ type: T.Type, at index: Int) -> T {
        return T(from: components[index])
    }
}
