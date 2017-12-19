//
//  RSAKeys.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation

public struct RSAPublicKey: JWK {
    public let keyType: KeyType
    public let parameters: [String : Any]
    
    public let n: String
    public let e: String
    
    public subscript(parameter: String) -> Any? {
        return parameters[parameter]
    }
    
    init(n: String, e: String) {
        self.keyType = .RSA
        self.n = n
        self.e = e
        
        self.parameters =  [
            "keyType": keyType.rawValue,
            "n": n,
            "e": e
        ]
    }
}

public struct RSAPrivateKey: JWK {
    public let keyType: KeyType
    public let parameters: [String : Any]
    
    public let n: String
    public let e: String
    public let d: String
    
    public subscript(parameter: String) -> Any? {
        return parameters[parameter]
    }
    
    init(n: String, e: String, d: String) {
        self.keyType = .RSA
        self.n = n
        self.e = e
        self.d = d
        
        self.parameters = [
            "keyType": keyType.rawValue,
            "n": n,
            "e": e,
            "d": d
        ]
    }
}

public typealias RSAKeyPair = RSAPrivateKey
