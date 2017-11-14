//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 19/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSADecrypter: AsymmetricDecrypter {
    let privateKey: SecKey
    
    func decrypt(_ ciphertext: Data) -> Data? {
        return "decryptedKey".data(using: .utf8)
    }
}
