//
//  JWKBuilder.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation

internal enum JWKType {
    case publicKey
    case privateKey
    case keyPair
}

internal protocol JWKBuilder {
    associatedtype KeyDataType
    
    func set(publicKey: KeyDataType) -> Self
    func set(privateKey: KeyDataType) -> Self
    
    func typeToBuild() -> JWKType?
    
    func build() -> JWK?
}
