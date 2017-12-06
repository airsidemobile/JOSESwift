//
//  AESDecrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//

import Foundation
import IDZSwiftCommonCrypto
import CommonCrypto

/// A `SymmetricDecrypter` to decrypt a cipher text with an `AES` algorithm.
public struct AESDecrypter: SymmetricDecrypter {

    // TODO: Refactor this method to be more generic, see: JOSE-79
    func decrypt(_ context: SymmetricDecryptionContext, with symmetricKey: Data, using algorithm: SymmetricEncryptionAlgorithm) throws -> Data {
        // Check if the key length contains both HMAC key and the actual symmetric key.
        guard algorithm.checkKeyLength(for: symmetricKey) else {
            throw EncryptionError.keyLengthNotSatisfied
        }

        // Get the two keys for the HMAC and the symmetric encryption.
        let keys = try algorithm.retrieveKeys(from: symmetricKey)
        let hmacKey = keys.hmacKey
        let decryptionKey = keys.encryptionKey

        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
        var concatData = context.additionalAuthenticatedData
        concatData.append(context.initializationVector)
        concatData.append(context.ciphertext)
        concatData.append(context.additionalAuthenticatedData.getByteLengthAsOctetHexData())
        
        // Calculate the HMAC for the concatenated input data and compare it with the reference authentication tag, return true if it matches (authenticated), false (not authenticated) otherwise.
        let hmacOutput = HMAC.calculate(from: concatData, with: hmacKey, using: algorithm.ccAlgorithms.hmacAlgorithm)
        
        guard context.authenticationTag == algorithm.authenticationTag(for: hmacOutput) else {
            throw EncryptionError.hmacNotAuthenticated
        }

        // Decrypt the cipher text with a symmetric decryption key, a symmetric algorithm and the initialization vector, return the plaintext if no error occured.
        let plaintext = try aesDecrypt(context.ciphertext, decryptionKey: decryptionKey, using: algorithm.ccAlgorithms.aesAlgorithm, and: context.initializationVector)

        return plaintext
    }

    /**
     Decrypts a cipher text using a given `AES` algorithm, the corresponding symmetric key and an initialization vector.
     - Parameters:
        - ciphertext: The encrypted cipher text to decrypt.
        - decryptionKey: The symmetric key.
        - algorithm: The algorithm used to decrypt the cipher text.
        - initializationVector: The initial block.
     
     - Throws:
        - `EncryptionError.decryptingFailed(description: String)`: If the encryption failed with a specific error.
     
     - Returns: The plain text (decrypted cipher text).
     */
    func aesDecrypt(_ ciphertext: Data, decryptionKey: Data, using algorithm: CCAlgorithm, and initializationVector: Data) throws -> Data {
        let dataLength = ciphertext.count
        let decryptLength  = size_t(dataLength + kCCBlockSizeAES128)
        var decryptData = Data(count:decryptLength)

        let keyLength = size_t(kCCKeySizeAES256)
        let options = CCOptions(kCCOptionPKCS7Padding)

        var numBytesEncrypted: size_t = 0

        let decryptStatus = decryptData.withUnsafeMutableBytes {decryptBytes in
            ciphertext.withUnsafeBytes {dataBytes in
                initializationVector.withUnsafeBytes {ivBytes in
                    decryptionKey.withUnsafeBytes {keyBytes in
                        CCCrypt(CCOperation(kCCDecrypt),
                                algorithm,
                                options,
                                keyBytes, keyLength,
                                ivBytes,
                                dataBytes, dataLength,
                                decryptBytes, decryptLength,
                                &numBytesEncrypted)
                    }
                }
            }
        }

        if UInt32(decryptStatus) == UInt32(kCCSuccess) {
            decryptData.removeSubrange(numBytesEncrypted..<decryptLength)
        } else {
            throw EncryptionError.decryptingFailed(description: "Decryption failed with CryptoStatus: \(decryptStatus).")
        }

        return decryptData
    }
}
