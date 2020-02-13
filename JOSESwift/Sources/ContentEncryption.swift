//
//  ContentEncryption.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//

import Foundation

struct ContentEncryptionContext {
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

protocol ContentEncrypter {
    func encrypt(header: JWEHeader, payload: Payload) throws -> ContentEncryptionContext
}

extension ContentEncryptionAlgorithm {
    func makeContentEncrypter(contentEncryptionKey: Data) -> ContentEncrypter {
        switch self {
        case .A128CBCHS256, .A256CBCHS512:
            return AESCBCEncryption(contentEncryptionAlgorithm: self, contentEncryptionKey: contentEncryptionKey)
        }
    }
}
