//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 19/10/2017.
//

import Foundation

public struct RSADecrypter: AsymmetricDecrypter {
    let privateKey: SecKey
    
    func decrypt(_ ciphertext: Data) throws -> Data {
        // Todo: Throw error if necessary.
        return "decryptedKey".data(using: .utf8)!
    }
}
