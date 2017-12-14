//
//  JWKBuilder.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation

protocol JWKBuilderProtocol {
    associatedtype KeyDataType
    
    func set(publicKey: KeyDataType) -> Self
    func set(privateKey: KeyDataType) -> Self
    
    func build() -> JWK?
}
