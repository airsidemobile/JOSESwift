//
//  Signature.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 25/09/2017.
//

import Foundation

public struct Signature {
    fileprivate let signature: Data
    
    public init(_ signature: Data) {
        self.signature = signature
    }
    
    internal init?(from signer: Signer, using header: JWSHeader, and payload: Payload) {
        if let signature = try? signer.sign(Signature.signingInput(from: [header, payload]), using: header.algorithm!) {
            self.init(signature)
            return
        }
        
        return nil
    }
    
    internal func validate(with verifier: Verifier, against header: JWSHeader, and payload: Payload) -> Bool {
        guard let result = try? verifier.verify(signature, against: Signature.signingInput(from: [header, payload]), using: header.algorithm!) else {
            return false
        }
        
        return result
    }
    
    private static func signingInput(from components: [DataConvertible]) -> Data {
        let encodedComponents = components.map { component in
            return component.data().base64URLEncodedString()
        }
        let dot = "."
        return encodedComponents.joined(separator: dot).data(using: .ascii)!
    }
}

extension Signature: DataConvertible {    
    public func data() -> Data {
        return signature
    }
}
