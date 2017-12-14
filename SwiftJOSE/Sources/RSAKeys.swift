//
//  RSAKeys.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation

public struct RSAPublicKey: JWK {
    public let keyType: KeyType
    let n: String
    let e: String
    
    public var parameters: [String : Any] {
        return [
            "keyType": keyType.rawValue,
            "n": n,
            "e": e
        ]
    }
    
    init(n: String, e: String) {
        self.keyType = .RSA
        self.n = n
        self.e = e
    }
}

struct RSAKeyPair: JWK {
    public let keyType: KeyType
    let n: String
    let e: String
    let d: String
    
    public var parameters: [String : Any] {
        return [
            "keyType": keyType.rawValue,
            "n": n,
            "e": e,
            "d": d
        ]
    }
    
    init(n: String, e: String, d: String) {
        self.keyType = .RSA
        self.n = n
        self.e = e
        self.d = d
    }
}
