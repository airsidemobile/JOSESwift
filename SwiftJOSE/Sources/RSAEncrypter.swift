//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSAEncrypter: AsymmetricEncrypter {
    let publicKey: SecKey
    
    func encrypt(_ plaintext: Data) throws -> Data {
        // Todo: Throw error if necessary.
        return "encryptedKey".data(using: .utf8)!
    }
}
