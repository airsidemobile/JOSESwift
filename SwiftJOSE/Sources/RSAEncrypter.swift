//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//

import Foundation

public struct RSAEncrypter: AsymmetricEncrypter {
    let publicKey: SecKey
    
    func encrypt(_ plaintext: Data) throws -> Data {
        // Todo: Throw error if necessary.
        return "encryptedKey".data(using: .utf8)!
    }
}
