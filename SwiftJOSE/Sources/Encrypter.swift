//
//  Encrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//

import Foundation

public enum EncryptionError: Error, Equatable {
    case encryptionAlgorithmNotSupported
    case plainTextLengthNotSatisfied
    case cipherTextLenghtNotSatisfied
    case encryptingFailed(description: String)
    case contentEncryptionKeyConversionFailed
    case decryptingFailed(description: String)
    
    public static func ==(lhs: EncryptionError, rhs: EncryptionError) -> Bool {
        switch (lhs, rhs) {
        case (.cipherTextLenghtNotSatisfied, .cipherTextLenghtNotSatisfied):
            return true
        case (.plainTextLengthNotSatisfied, .plainTextLengthNotSatisfied):
            return true
        default:
            return false
        }
    }
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
    
    func isCipherTextLenghtSatisfied(_ cipherText: Data, for privateKey: SecKey) -> Bool {
        switch self {
        case .RSAPKCS:
            return cipherText.count == SecKeyGetBlockSize(privateKey)
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
    func randomCEK(for algorithm: SymmetricEncryptionAlgorithm) -> Data
    func randomIV(for algorithm: SymmetricEncryptionAlgorithm) -> Data
    func encrypt(_ plaintext: Data, aad: Data, with symmetricKey: Data, using algorithm: SymmetricEncryptionAlgorithm) throws -> SymmetricEncryptionContext
}

public struct EncryptionContext {
    let encryptedKey: Data
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

public struct SymmetricEncryptionContext {
    let ciphertext: Data
    let authenticationTag: Data
    let initializationVector: Data
}

public struct Encrypter {
    let asymmetric: AsymmetricEncrypter
    let symmetric: SymmetricEncrypter
    
    public init(keyEncryptionAlgorithm: AsymmetricEncryptionAlgorithm, keyEncryptionKey kek: SecKey, contentEncyptionAlgorithm: SymmetricEncryptionAlgorithm) throws {
        // Todo: Find out which available encrypters support the specified algorithms.
        // Throw `algorithmNotSupported` error if necessary.
        // See https://mohemian.atlassian.net/browse/JOSE-58.
        
        self.asymmetric = RSAEncrypter(publicKey: kek)
        self.symmetric = AESEncrypter()
    }
    
    func encrypt(header: JWEHeader, payload: Payload) throws -> EncryptionContext {
        // Todo: This check might be redundant since it will already be done in the init.
        // See https://mohemian.atlassian.net/browse/JOSE-58.
        guard let alg = header.algorithm, let enc = header.encryptionAlgorithm else {
            throw EncryptionError.encryptionAlgorithmNotSupported
        }
        
        let cek = symmetric.randomCEK(for: enc)
        let encryptedKey = try asymmetric.encrypt(cek, using: alg)
        let symmetricContext = try symmetric.encrypt(payload.data(), aad: header.data(), with: cek, using: enc)
        
        return EncryptionContext(
            encryptedKey: encryptedKey,
            ciphertext: symmetricContext.ciphertext,
            authenticationTag: symmetricContext.authenticationTag,
            initializationVector: symmetricContext.initializationVector
        )
    }
}
