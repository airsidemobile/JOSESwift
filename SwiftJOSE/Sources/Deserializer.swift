//
//  Deserializer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 26/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

protocol CompactDeserializable {
    init(from deserializer: CompactDeserializer)
}

protocol CompactDeserializer {
    func deserialize<T: JOSEObjectComponent>(_ type: T.Type, at index: Int) -> T
}

public struct Deserializer {
    func deserialize<T: CompactDeserializable>(_ type: T.Type, fromCompactSerialization compactSerialization: String) -> T {
        let components = compactSerialization.components(separatedBy: ".").map { Data(base64URLEncoded: $0) }
        let deserializer = _CompactDeserializer(components: components)
        return T(from: deserializer)
    }
}

fileprivate struct _CompactDeserializer: CompactDeserializer {
    let components: [Data]
    
    func deserialize<T: JOSEObjectComponent>(_ type: T.Type, at index: Int) -> T {
        return T(from: components[index])
    }
}
