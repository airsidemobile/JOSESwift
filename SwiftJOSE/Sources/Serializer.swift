//
//  Serialization.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

protocol CompactSerializable {
    func serialize(to serializer: inout CompactSerializer)
}

protocol CompactSerializer {
    var components: [JOSEObjectComponent] { get }
    mutating func serialize<T: JOSEObjectComponent>(_ object: T)
}

public struct Serializer {
    func compact<T: CompactSerializable>(_ object: T) -> String {
        var serializer: CompactSerializer = _CompactSerializer()
        object.serialize(to: &serializer)
        let base64URLEncodings = serializer.components.map { $0.data().base64URLEncodedString() }
        return base64URLEncodings.joined(separator: ".")
    }
}

fileprivate struct _CompactSerializer: CompactSerializer {
    var components: [JOSEObjectComponent] = []
    
    mutating func serialize<T: JOSEObjectComponent>(_ object: T) {
        components.append(object)
    }
}
