//
//  Encrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//

import Foundation

public enum EncryptionError: Error {
    case encryptionAlgorithmNotSupported
    case plainTextLengthNotSatisfied
    case encryptingFailed(description: String)
    case decryptingFailed(descritpion: String)
}

public enum AsymmetricEncryptionAlgorithm: String {
    case RSAPKCS = "RSA1_5"
    
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .RSAPKCS:
            return .rsaEncryptionPKCS1
        }
    }
    
    /// Checks if the plain text length does not exceed the maximum for the chosen algorithm and the corresponding public key.
    func isPlainTextLengthSatisfied(_ plainText: Data, for publicKey: SecKey) -> Bool {
        switch self {
        case .RSAPKCS:
            // For detailed information about the allowed plain text length for RSAES-PKCS1-v1_5, please refer to the RFC(https://tools.ietf.org/html/rfc3447#section-7.2).
            return plainText.count < (SecKeyGetBlockSize(publicKey) - 11)
        }
    }
}

public enum SymmetricEncryptionAlgorithm: String {
    case AESGCM256 = "A256GCM"
    
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        default:
            return nil
        }
    }
}

internal protocol AsymmetricEncrypter {
    /// Initializes an `AsymmetricEncrypter` with a specified public key.
    init(publicKey: SecKey)
    
    /**
     Encrypts a plain text using a given `AsymmetricEncryptionAlgorithm` and the corresponding public key.
     - Parameters:
        - plaintext: The plain text to encrypt.
        - algorithm: The algorithm used to encrypt the plain text.
     
     - Throws:
        - `EncryptionError.encryptionAlgorithmNotSupported`: If the provided algorithm is not supported for encryption.
        - `EncryptionError.plainTextLengthNotSatisfied`: If the plain text length exceeds the allowed maximum.
        - `EncryptionError.encryptingFailed(description: String)`: If the encryption failed with a specific error.
     
     - Returns: The cipher text (encrypted plain text).
     */
    func encrypt(_ plaintext: Data, using algorithm: AsymmetricEncryptionAlgorithm) throws -> Data
}

internal protocol SymmetricEncrypter {
    init(symmetricKey: SecKey)
    func encrypt(_ plaintext: Data, with aad: Data) throws -> EncryptionContext
}

public struct EncryptionContext {
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

public struct Encrypter {
    let symmetricEncrypter: SymmetricEncrypter
    let encryptedKey: Data
    
    public init(keyEncryptionAlgorithm: AsymmetricEncryptionAlgorithm, keyEncryptionKey kek: SecKey, contentEncyptionAlgorithm: SymmetricEncryptionAlgorithm, contentEncryptionKey cek: SecKey) throws {
        // Todo: Find out which available encrypters support the specified algorithms and throw `algorithmNotSupported` error if necessary. See https://mohemian.atlassian.net/browse/JOSE-58.
        self.symmetricEncrypter = AESEncrypter(symmetricKey: cek)
        
        // Todo: Convert key to correct representation (check RFC).
        var error: Unmanaged<CFError>?
        let keyData = SecKeyCopyExternalRepresentation(cek, &error)! as Data;
        self.encryptedKey = try RSAEncrypter(publicKey: kek).encrypt(keyData, using: keyEncryptionAlgorithm)
    }
    
    func encrypt(header: JWEHeader, payload: Payload) throws -> EncryptionContext {
        return try symmetricEncrypter.encrypt(payload.data(), with: header.data().base64URLEncodedData())
    }
}
