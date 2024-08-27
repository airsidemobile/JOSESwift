//
//  JOSEDeserializer.swift
//  JOSESwift
//
//  Created by Daniel Egger on 26/09/2017.
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

public protocol CompactDeserializable {
    static var componentCount: Int { get }
    init(from deserializer: CompactDeserializer) throws
}

public protocol CompactDeserializer {
    func deserialize<T: DataConvertible>(_ type: T.Type, at index: Int) throws -> T
}

public struct JOSEDeserializer {
    public init() { }

    public func deserialize<T: CompactDeserializable>(_ type: T.Type, fromCompactSerialization compactSerialization: String) throws -> T {
        let encodedComponents = compactSerialization.components(separatedBy: ".")

        guard encodedComponents.count == type.componentCount else {
            throw JOSESwiftError.invalidCompactSerializationComponentCount(count: encodedComponents.count)
        }

        let decodedComponents = try encodedComponents.map { (component: String) throws -> Data in
            guard let data = Data(base64URLEncoded: component) else {
                throw JOSESwiftError.componentNotValidBase64URL(component: component)
            }
            return data
        }

        let deserializer = _CompactDeserializer(components: decodedComponents)

        return try T(from: deserializer)
    }
}

private struct _CompactDeserializer: CompactDeserializer {
    let components: [Data]

    func deserialize<T: DataConvertible>(_ type: T.Type, at index: Int) throws -> T {
        let componentData = components[index]
        guard let component = T(componentData) else {
            throw JOSESwiftError.componentCouldNotBeInitializedFromData(data: componentData)
        }

        return component
    }
}

public enum ComponentCompactSerializedIndex {
    static let jwsHeaderIndex = 0
    static let jwsPayloadIndex = 1
    static let jwsSignatureIndex = 2
    static let jweHeaderIndex = 0
    static let jweEncryptedKeyIndex = 1
    static let jweInitializationVectorIndex = 2
    static let jweCiphertextIndex = 3
    static let jweAuthenticationTagIndex = 4
}
