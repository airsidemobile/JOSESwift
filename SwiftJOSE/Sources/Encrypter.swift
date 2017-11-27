//
//  Encrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//

import Foundation

public enum EncryptionError: Error, Equatable {
    case keyEncryptionAlgorithmNotSupported
    case contentEncryptionAlgorithmNotSupported
    case plainTextLengthNotSatisfied
    case cipherTextLenghtNotSatisfied
    case encryptingFailed(description: String)
    case decryptingFailed(descritpion: String)
    
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
    case RSAOAEP = "RSA-OAEP"
    case RSAPKCS = "RSA1_5"
    
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        case .RSAPKCS:
            return .rsaEncryptionPKCS1
        default:
            return nil
        }
    }
    
    func isPlainTextLengthSatisfied(_ plainText: Data, for publicKey: SecKey) -> Bool {
        switch self {
        case .RSAPKCS:
            return plainText.count < (SecKeyGetBlockSize(publicKey) - 11)
        default:
            return false
        }
    }
    
    func isCipherTextLenghtSatisfied(_ cipherText: Data, for privateKey: SecKey) -> Bool {
        switch self {
        case .RSAPKCS:
            return cipherText.count == SecKeyGetBlockSize(privateKey)
        default:
            return false
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
    init(publicKey: SecKey)
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
