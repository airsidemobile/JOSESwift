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
    case contentEncryptionKeyConversionFailed
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
    var publicKey: SecKey { get }
    init(publicKey: SecKey)
    func encrypt(_ plaintext: Data, using algorithm: AsymmetricEncryptionAlgorithm) throws -> Data
}

internal protocol SymmetricEncrypter {
    var symmetricKey: SecKey { get }
    init(symmetricKey: SecKey)
    func encrypt(_ plaintext: Data, aad: Data, using algorithm: SymmetricEncryptionAlgorithm) throws -> SymmetricEncryptionContext
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
        
         // Todo: Generate CEK using a trusted cryptography library.
        let cek = kek
        
        self.asymmetric = RSAEncrypter(publicKey: kek)
        self.symmetric = AESEncrypter(symmetricKey: cek)
    }
    
    func encrypt(header: JWEHeader, payload: Payload) throws -> EncryptionContext {
        guard let alg = header.algorithm else { throw EncryptionError.keyEncryptionAlgorithmNotSupported }
        guard let enc = header.encryptionAlgorithm else { throw EncryptionError.contentEncryptionAlgorithmNotSupported }
        
        // Todo: Convert key to correct representation (check RFC).
        var error: Unmanaged<CFError>?
        guard let cek = SecKeyCopyExternalRepresentation(symmetric.symmetricKey, &error) else {
            throw EncryptionError.contentEncryptionKeyConversionFailed
        }
        
        let encryptedKey = try asymmetric.encrypt(cek as Data, using: alg)
        let symmetricContext = try symmetric.encrypt(payload.data(), aad: header.data(), using: enc)
        
        return EncryptionContext(
            encryptedKey: encryptedKey,
            ciphertext: symmetricContext.ciphertext,
            authenticationTag: symmetricContext.authenticationTag,
            initializationVector: symmetricContext.initializationVector
        )
    }
}
