//
//  SecKeyExtensions.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation
import Security

public extension SecKey {
    public class SecKeyJWKBuilder: JWKBuilder {
        typealias KeyDataType = SecKey
        
        private var publicKey: SecKey?
        private var privateKey: SecKey?
        
        public init() { }
        
        public func set(publicKey: SecKey) -> Self {
            self.publicKey = publicKey
            return self
        }
        
        public func set(privateKey: SecKey) -> Self {
            self.privateKey = privateKey
            return self
        }
        
        internal func typeToBuild() -> JWKType? {
            // No keys set
            guard (publicKey != nil) || (privateKey != nil) else {
                return nil
            }
            
            // Only public key set
            if (publicKey != nil) && (privateKey == nil) {
                return .publicKey
            }
            
            // Only private key set
            if (publicKey == nil) && (privateKey != nil) {
                return .privateKey
            }
            
            // Both public and private key set
            return .keyPair
        }
        
        public func build() -> JWK? {
            guard let type = typeToBuild() else {
                return nil
            }
            
            // Todo: Do conversions from SecKey to modulus/exponent representation.
            // See https://mohemian.atlassian.net/browse/JOSE-91.
            // See https://github.com/henrinormak/Heimdall/blob/master/Heimdall/Heimdall.swift.
            
            switch type {
            case .publicKey:
                return RSAPublicKey(n: "0vx...Kgw", e: "AQAB")
            case .privateKey:
                return RSAPrivateKey(n: "0vx...Kgw", e: "AQAB", d: "X4c...C8Q")
            case .keyPair:
                return RSAKeyPair(n: "0vx...Kgw", e: "AQAB", d: "X4c...C8Q")
            }
        }
    }
}
