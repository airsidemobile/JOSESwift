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
    func encrypt(_ plaintext: Data, aad: Data, with symmetricKey: SecKey, using algorithm: SymmetricEncryptionAlgorithm) throws -> SymmetricEncryptionContext
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
        guard let alg = header.algorithm else { throw EncryptionError.keyEncryptionAlgorithmNotSupported }
        guard let enc = header.encryptionAlgorithm else { throw EncryptionError.contentEncryptionAlgorithmNotSupported }
        
        // Todo: Generate CEK using a trusted crypto library.
        let cekData = Data(count: 256)
        let tag = "todo.com".data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecValueRef as String: cekData,
            kSecReturnRef as String: kCFBooleanTrue
        ]
        var item: CFTypeRef?
        SecItemAdd(query as CFDictionary, &item)
        let cek = item as! SecKey
        
        let encryptedKey = try asymmetric.encrypt(cekData, using: alg)
        let symmetricContext = try symmetric.encrypt(payload.data(), aad: header.data(), with: cek, using: enc)
        
        return EncryptionContext(
            encryptedKey: encryptedKey,
            ciphertext: symmetricContext.ciphertext,
            authenticationTag: symmetricContext.authenticationTag,
            initializationVector: symmetricContext.initializationVector
        )
    }
}
