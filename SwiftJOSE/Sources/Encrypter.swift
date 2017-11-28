//
//  Encrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 13/10/2017.
//

import Foundation

public enum EncryptionError: Error {
    case keyEncryptionAlgorithmNotSupported
    case contentEncryptionAlgorithmNotSupported
    case encryptingFailed(description: String)
    case decryptingFailed(descritpion: String)
}

public enum AsymmetricEncryptionAlgorithm: String {
    case RSAOAEP = "RSA-OAEP"
    
    var secKeyAlgorithm: SecKeyAlgorithm? {
        switch self {
        default:
            return nil
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
    func encrypt(_ plaintext: Data) throws -> Data
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
    let asymmetricEncrypter: AsymmetricEncrypter
    let symmetricEncrypter: SymmetricEncrypter
    
    public init(keyEncryptionAlgorithm: AsymmetricEncryptionAlgorithm, keyEncryptionKey kek: SecKey, contentEncyptionAlgorithm: SymmetricEncryptionAlgorithm) throws {
        // Todo: Find out which available encrypters support the specified algorithms and throw `algorithmNotSupported` error if necessary.
        // See https://mohemian.atlassian.net/browse/JOSE-58.
        
        let cek = kek // Todo: Generate CEK
        
        self.symmetricEncrypter = AESEncrypter(symmetricKey: cek)
        self.asymmetricEncrypter = RSAEncrypter(publicKey: kek)
    }
    
    func encrypt(header: JWEHeader, payload: Payload) throws -> EncryptionContext {
        return try symmetricEncrypter.encrypt(payload.data(), with: header.data().base64URLEncodedData())
    }
}
