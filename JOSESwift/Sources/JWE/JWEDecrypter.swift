//
//  JWEDecrypter.swift
//  JOSESwift
//
//  Created by Prem Eide on 05/12/2025.
//

import Foundation
public protocol JWEDecrypter {
    func decrypt(_ context: DecryptionContext) throws -> Data
}

public struct DecryptionContext {
    let header: JWEHeader
    let encryptedKey: Base64URL
    let initializationVector: Base64URL
    let ciphertext: Base64URL
    let authenticationTag: Base64URL
    let aad: Data
}
