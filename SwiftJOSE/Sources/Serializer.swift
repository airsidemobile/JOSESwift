//
//  JOSESerializer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 21/09/2017.
//

import Foundation

public protocol CompactSerializable {
    func serialize(to serializer: inout CompactSerializer)
}

public protocol CompactSerializer {
    var components: [DataConvertible] { get }
    mutating func serialize<T: DataConvertible>(_ object: T)
}

public struct JOSESerializer {
    public func serialize<T: CompactSerializable>(compact object: T) -> String {
        var serializer: CompactSerializer = _CompactSerializer()
        object.serialize(to: &serializer)
        let base64URLEncodings = serializer.components.map { component in component.data().base64URLEncodedString() }
        return base64URLEncodings.joined(separator: ".")
    }
}

private struct _CompactSerializer: CompactSerializer {
    var components: [DataConvertible] = []

    mutating func serialize<T: DataConvertible>(_ object: T) {
        components.append(object)
    }
}
