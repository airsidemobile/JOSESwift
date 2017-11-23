//
//  Decrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 17/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

internal protocol AsymmetricDecrypter {
    init(privateKey: SecKey)
    func decrypt(_ ciphertext: Data, using algorithm: AsymmetricEncryptionAlgorithm) throws -> Data
}

internal protocol SymmetricDecrypter {
    init(symmetricKey: Data)
    func decrypt(_ ciphertext: Data, initializationVector: Data, additionalAuthenticatedData: Data, authenticationTag: Data) throws -> Data
}

public struct DecryptionContext {
    let header: JWEHeader
    let encryptedKey: Data
    let initializationVector: Data
    let ciphertext: Data
    let authenticationTag: Data
}

public struct Decrypter {
    let asymmetricDecrypter: AsymmetricDecrypter
    
    public init(keyDecryptionAlgorithm: AsymmetricEncryptionAlgorithm, keyDecryptionKey kdk: SecKey) throws {
        // Todo: Find out which available encrypter supports the specified algorithm and throw error if necessary. See https://mohemian.atlassian.net/browse/JOSE-58.
        self.asymmetricDecrypter = RSADecrypter(privateKey: kdk)
    }
    
    func decrypt(_ context: DecryptionContext) throws -> Data {
        let cdk = try asymmetricDecrypter.decrypt(context.encryptedKey, using: context.header.algorithm!)
        
        // Todo: Find out which available decrypter supports the specified algorithm and throw error if necessary. See https://mohemian.atlassian.net/browse/JOSE-58.
        return try AESDecrypter(symmetricKey: cdk).decrypt(
            context.ciphertext,
            initializationVector: context.initializationVector,
            additionalAuthenticatedData: context.header.data().base64URLEncodedData(),
            authenticationTag: context.authenticationTag
        )
    }
}
