//
//  JOSEDeserializer.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 26/09/2017.
//

import Foundation

enum DeserializationError: Error {
    case wrongDataEncoding(data: Data)
    case invalidCompactSerializationComponentCount(count: Int)
    case componentNotValidBase64URL(component: String)
    case componentCouldNotBeInitializedFromData(data: Data)
}

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
            throw DeserializationError.invalidCompactSerializationComponentCount(count: encodedComponents.count)
        }

        let decodedComponents = try encodedComponents.map { (component: String) throws -> Data in
            guard let data = Data(base64URLEncoded: component) else {
                throw DeserializationError.componentNotValidBase64URL(component: component)
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
            throw DeserializationError.componentCouldNotBeInitializedFromData(data: componentData)
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
