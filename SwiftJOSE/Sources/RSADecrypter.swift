//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 19/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public struct RSADecrypter: Decrypter {
    let kdk: String
    
    public init(privateKey kdk: String) {
        self.kdk = kdk
    }
    
    public func decrypt(ciphertext: Data, with header: JWEHeader, and additionalInformation: JWEAdditionalCryptoInformation) -> Data? {
        return "so cool".data(using: .utf8)!
    }
}
