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

        let additionalAuthenticatedDataLength = getAdditionalAuthenticatedDataLength(from: context.additionalAuthenticatedData)

        // Put together the input data for the HMAC. It consists of A || IV || E || AL.
        var concatData = context.additionalAuthenticatedData
        concatData.append(context.initializationVector)
        concatData.append(context.ciphertext)
        concatData.append(additionalAuthenticatedDataLength)

        // Calculate the HMAC for the concatenated input data and compare it with the reference authentication tag.
        guard authenticateHmac(context.authenticationTag, input: concatData, hmacKey: hmacKey, using: algorithm.algorithms.hmacAlgorithm) else {
            throw EncryptionError.hmacNotAuthenticated
        }

        // Decrypt the cipher text with a symmetric decryption key, a symmetric algorithm and the initialization vector, return the plaintext if no error occured.
        let plaintext = try aesDecrypt(context.ciphertext, decryptionKey: decryptionKey, using: algorithm.algorithms.aesAlgorithm, and: context.initializationVector)

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

    /**
     Checks if the reference authentication tag matches with, from the input calculated, authentication tag.
     - Parameters:
        - authenticationTag: The reference authentication tag received with the message.
        - input: The concatenated data in the format A || IV || E || AL.
        - algorithm: The algorithm used to calculate the HMAC.
        - initializationVector: The initial block.
     
     - Returns: True if the message is authenticated (the authentication tags match), false if the message is not authenticated (the authentication tags do not match)
     */
    // TODO: Refactor this see: JOSE-81
    func authenticateHmac(_ authenticationTag: Data, input: Data, hmacKey: Data, using algorithm: CCAlgorithm) -> Bool {
        let keyLength = size_t(kCCKeySizeAES256)
        var hmacOutData = Data(count: 64)

        hmacOutData.withUnsafeMutableBytes { hmacOutBytes in
            hmacKey.withUnsafeBytes { hmacKeyBytes in
                input.withUnsafeBytes { inputBytes in
                    CCHmac(algorithm, hmacKeyBytes, keyLength, inputBytes, input.count, hmacOutBytes)
                }
            }
        }

        return authenticationTag == hmacOutData.subdata(in: 0..<32)
    }

    // TODO: Refactor this see: JOSE-82
    func getAdditionalAuthenticatedDataLength(from additionalAuthenticatedData: Data) -> Data {
        let dataLength = UInt64(additionalAuthenticatedData.count * 8)
        var dataLengthInHex = String(dataLength, radix: 16, uppercase: false)

        var additionalAuthenticatedDataLengthBytes = [UInt8](repeatElement(0x00, count: 8))

        var dataIndex = additionalAuthenticatedDataLengthBytes.count-1
        for i in stride(from: 0, to: dataLengthInHex.count, by: 2) {
            var hexChunk = ""
            if dataLengthInHex.count == 1 {
                hexChunk = dataLengthInHex
            } else {
                let endIndex = dataLengthInHex.index(dataLengthInHex.endIndex, offsetBy: -i)
                let startIndex = dataLengthInHex.index(endIndex, offsetBy: -2)
                let range = Range(uncheckedBounds: (lower: startIndex, upper: endIndex))
                hexChunk = String(dataLengthInHex[range])
                dataLengthInHex.removeLast(2)
            }

            if let hexBytes = UInt8(hexChunk, radix: 16) {
                additionalAuthenticatedDataLengthBytes[dataIndex] = hexBytes
            }

            dataIndex -= 1
        }

        return Data(bytes: additionalAuthenticatedDataLengthBytes)
    }
}
