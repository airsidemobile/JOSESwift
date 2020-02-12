//
//  ContentEncryption.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//

import Foundation

public struct ContentEncryptionContext {
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

protocol ContentEncryptionImplementation {
    func encrypt(header: JWEHeader, payload: Payload, with contentEncryptionKey: Data) throws -> ContentEncryptionContext
}

enum ContentEncryption {
    static func makeImplementation<KeyType>(contentEncryptionAlgorithm: ContentEncryptionAlgorithm, contentEncryptionKey: KeyType) -> ContentEncryptionImplementation? {
        switch contentEncryptionAlgorithm {
        case .A128CBCHS256, .A256CBCHS512:
            guard type(of: contentEncryptionKey) is AESCBCEncryption.KeyType.Type else { return nil }
            return AESCBCEncryption(contentEncryptionAlgorithm: contentEncryptionAlgorithm, contentEncryptionKey: contentEncryptionKey as! AESCBCEncryption.KeyType)
        }
    }
}
