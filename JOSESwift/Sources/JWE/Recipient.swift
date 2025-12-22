//
//  Recipient.swift
//  JOSESwift
//
//  Created by Prem Eide on 12/12/2025.
//

/// Individual recipient in a JWE object serialisable to JSON
public struct Recipient {
    /// The per-recipient unprotected header
    public let unprotectedHeader: UnprotectedHeader?
    /// The encrypted key
    public let encryptedKey: Base64URL
    
    public init(unprotectedHeader: UnprotectedHeader?, encryptedKey: Base64URL) {
        self.unprotectedHeader = unprotectedHeader
        self.encryptedKey = encryptedKey
    }
    
    /// Turn into a JSON object that matches JWE JSON Serialization
    public func toJSONObject() -> [String: Any] {
        var json: [String: Any] = ["encrypted_key": encryptedKey.value]
        
        if let header = unprotectedHeader {
            json["header"] = header.parameters
        }
        
        return json
    }
}
