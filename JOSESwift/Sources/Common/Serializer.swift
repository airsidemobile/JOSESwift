//
//  JOSESerializer.swift
//  JOSESwift
//
//  Created by Daniel Egger on 21/09/2017.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
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
