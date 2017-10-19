//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 19/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct AESDecrypter: Decrypter {
    let kdk: String
    
    public init(privateKey kdk: String) {
        self.kdk = kdk
    }
    
    public func decrypt(ciphertext: Data, withHeader: JWEHeader, encryptedKey: Data, initializationVector: Data, authenticationTag: Data) -> Data? {
        return "plaintext".data(using: .utf8)!
    }
}
