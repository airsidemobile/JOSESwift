//
//  JWEObjectJSON.swift
//  JOSESwift
//
//  Created by Prem Eide on 02/12/2025.
//

import Foundation

/// JSON Web Encryption (JWE) secured object with JSON serialisation
/// https://www.rfc-editor.org/rfc/rfc7516#section-7.2
public struct JWEObjectJSON {
    
    /// The integrity-protected shared header
    public let protected: JWEHeader
    
    /// The recipients list.
    public let recipients: [Recipient]
    
    /// The initialisation vector
    public let iv: Base64URL
    
    /// The cipher text
    public let cipherText: Base64URL
    
    /// The authentication tag
    public let tag: Base64URL
    
    /// The additional authenticated data
    public var aad: Data { // FIXME: Not always correct. See section-5.1 point 14.
        protected.data().base64URLEncodedData()
    }
    
    /// Creates a `JWEObjectJSON` by parsing the given JWE JSON serialization string.
    public init(jsonString: String) throws {
        let raw = try Self.parseJSONObject(jsonString)
        
        self.protected  = try Self.parseProtectedHeader(from: raw)
        self.cipherText = try Self.getBase64URL(forKey: "ciphertext", in: raw)
        self.iv         = try Self.getBase64URL(forKey: "iv", in: raw)
        self.tag        = try Self.getBase64URL(forKey: "tag", in: raw)
        self.recipients = try Self.parseRecipients(from: raw)
    }
    
    public func decrypt(using decrypter: JWEDecrypter) throws -> Payload {
        let context = DecryptionContext(
            header: protected,
            encryptedKey: try getEncryptedKey(),
            initializationVector: iv,
            ciphertext: cipherText,
            authenticationTag: tag,
            aad: aad
        )
        let decryptedData = try decrypter.decrypt(context)
        return Payload(decryptedData)
    }
    
    private func getEncryptedKey() throws -> Base64URL {
        if recipients.count == 1 {
            return recipients[0].encryptedKey
        }
        let recipientsList = recipients.map { $0.toJSONObject() }
        let recipientsMap = ["recipients": recipientsList]
        let jsonData = try JSONSerialization.data(withJSONObject: recipientsMap)
        return Base64URL(jsonData)
    }
}

extension JWEObjectJSON {
    
    static func parseJSONObject(_ jsonString: String) throws -> [String: Any] {
        let data = Data(jsonString.utf8)
        return try parseJSONObject(data)
    }
    
    static func parseJSONObject(_ jsonData: Data) throws -> [String: Any] {
        guard let raw = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            throw JWEObjectJSONError.invalidJSON
        }
        return raw
    }
    
    static func getBase64URL(forKey key: String, in raw: [String: Any]) throws -> Base64URL {
        guard let string = raw[key] as? String else {
            throw JWEObjectJSONError.missingField(key)
        }
        return Base64URL(string)
    }
    
    static func parseProtectedHeader(from raw: [String: Any]) throws -> JWEHeader {
        let protectedData = try getBase64URL(forKey: "protected", in: raw).decode()
        let headerAny = try JSONSerialization.jsonObject(with: protectedData)
        
        guard let headerParams = headerAny as? [String: Any] else {
            throw JWEObjectJSONError.invalidJSON
        }
        return try JWEHeader(parameters: headerParams)
    }
    
    static func parseRecipients(from raw: [String: Any]) throws -> [Recipient] {
        if let recipientsArray = raw["recipients"] as? [[String: Any]] {
            // General serialization
            return try recipientsArray.map { recipientJSON in
                guard let headerJSON = recipientJSON["header"] as? [String: Any] else {
                    throw JWEObjectJSONError.invalidJSON
                }
                let recipientHeader = UnprotectedHeader(parameters: headerJSON)
                let encryptedKey = try getBase64URL(forKey: "encrypted_key", in: recipientJSON)
                return Recipient(unprotectedHeader: recipientHeader, encryptedKey: encryptedKey)
            }
        } else {
            // Flattened serialization
            let encryptedKey = try getBase64URL(forKey: "encrypted_key", in: raw)
            return [Recipient(unprotectedHeader: nil, encryptedKey: encryptedKey)]
        }
    }
}

enum JWEObjectJSONError: Error {
    case invalidJSON
    case missingField(String)
}
