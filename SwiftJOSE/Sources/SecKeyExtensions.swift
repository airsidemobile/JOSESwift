//
//  SecKeyExtensions.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
//

import Foundation
import Security

public extension SecKey {
    public class JWKBuilder: JWKBuilderProtocol {
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
        
        public func build() -> JWK? {
            guard let _ = publicKey else {
                return nil
            }
            
            if let _ = privateKey {
                // Magically turn SecKeys into n, e, and d.
                return RSAKeyPair(n: "0vx...Kgw", e: "AQAB", d: "X4c...C8Q")
            }
            
            // Magically turn SecKeys into n and e.
            return RSAPublicKey(n: "0vx...Kgw", e: "AQAB")
        }
    }
}
