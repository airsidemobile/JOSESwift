//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 19/10/2017.
//

import Foundation

public struct RSADecrypter: AsymmetricDecrypter {
    let privateKey: SecKey
    
    func decrypt(_ ciphertext: Data) -> Data? {
        return "decryptedKey".data(using: .utf8)
    }
}
