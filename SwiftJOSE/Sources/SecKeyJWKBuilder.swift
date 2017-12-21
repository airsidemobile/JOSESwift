//
//  SecKeyJWKBuilder.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation
import Security

// Naming?
public class SecKeyJWKBuilder: JWKBuilder {
    typealias KeyDataType = SecKey
    
    private var publicKey: SecKey?
    private var privateKey: SecKey?
    private var parameters: [String: Any] = [:]
    
    public init() { }
    
    public func set(publicKey: SecKey) -> Self {
        self.publicKey = publicKey
        return self
    }
    
    public func set(privateKey: SecKey) -> Self {
        self.privateKey = privateKey
        return self
    }

    public func set(_ parameter: String, to value: Any) -> Self {
        parameters[parameter] = value
        return self
    }

    public func build() -> JWK? {
        // Todo: Impove before implementation https://mohemian.atlassian.net/browse/JOSE-94.

        // Todo: Do conversion from JWK modulus/exponent representation to SecKey.
        // See https://mohemian.atlassian.net/browse/JOSE-91.
        // See https://github.com/henrinormak/Heimdall/blob/master/Heimdall/Heimdall.swift.

        // Only public key set
        if (publicKey != nil) && (privateKey == nil) {
            return RSAPublicKey(n: "0vx...Kgw", e: "AQAB", additionalParameters: parameters)
        }

        // Only private key set
        if (publicKey == nil) && (privateKey != nil) {
            return RSAPrivateKey(n: "0vx...Kgw", e: "AQAB", d: "X4c...C8Q", additionalParameters: parameters)
        }

        // Both public and private key set
        if (publicKey != nil) && (privateKey != nil) {
            return RSAKeyPair(n: "0vx...Kgw", e: "AQAB", d: "X4c...C8Q", additionalParameters: parameters)
        }

        // No keys set
        return nil
    }
}

extension JWK {
    // Todo: Impove before implementation https://mohemian.atlassian.net/browse/JOSE-94.
    static func secKeyRepresentation() throws -> SecKey {
        // Todo: Do conversion from JWK modulus/exponent representation to SecKey.
        // See https://mohemian.atlassian.net/browse/JOSE-92.
        // See https://github.com/henrinormak/Heimdall/blob/master/Heimdall/Heimdall.swift.
        
        var item: CFTypeRef?
        return item as! SecKey
    }
}
