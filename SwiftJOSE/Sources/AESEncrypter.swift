//
//  AESEncrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 09.11.17.
//

import Foundation
import IDZSwiftCommonCrypto
import CommonCrypto

/// A `SymmetricEncrypter` to encrypt plaintext with an `AES` algorithm.
public struct AESEncrypter: SymmetricEncrypter {
    func randomCEK(for algorithm: SymmetricEncryptionAlgorithm) -> Data {
        // Todo: Generate CEK using a trusted cryptography library.
        // See: https://mohemian.atlassian.net/browse/JOSE-62.
        return Data(count: 64)
    }

    func randomIV(for algorithm: SymmetricEncryptionAlgorithm) -> Data {
        // Todo: Generate IV using a trusted cryptography library.
        // See: https://mohemian.atlassian.net/browse/JOSE-62.
        return "iv".data(using: .utf8)!
    }

    // TODO: Refactor this method to be more generic, see: JOSE-79
    func encrypt(_ plaintext: Data, with symmetricKey: Data, using algorithm: SymmetricEncryptionAlgorithm, additionalAuthenticatedData: Data) throws -> SymmetricEncryptionContext {

        // Generate random intitializationVector.
        // let iv = randomIV(for: algorithm)

        let iv = "1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04".hexadecimalToData()!

        // Check if the key length contains both HMAC key and the actual symmetric key.
        guard algorithm.checkKeyLength(for: symmetricKey) else {
            throw EncryptionError.keyLengthNotSatisfied
        }

        // Get the two keys for the HMAC and the symmetric encryption.
        let keys = try algorithm.retrieveKeys(from: symmetricKey)
        let hmacKey = keys.hmacKey
        let encryptionKey = keys.encryptionKey

        // Encrypt the plaintext with a symmetric encryption key, a symmetric encryption algorithm and an initialization vector,
        // return the ciphertext if no error occured.
        let cipherText = try aesEncrypt(plaintext, encryptionKey: encryptionKey, using: algorithm.ccAlgorithms.aesAlgorithm, and: iv)
        let additionalAuthenticatedDataLength = getAdditionalAuthenticatedDataLength(from: additionalAuthenticatedData)

        // Put the input data for the HMAC together. It consists of A || IV || E || AL.
        var concatData = additionalAuthenticatedData
        concatData.append(iv)
        concatData.append(cipherText)
        concatData.append(additionalAuthenticatedDataLength)

        // Calculate the HMAC with the concatenated input data, the HMAC key and the HMAC algorithm.
        let hmacOutput = HMAC.calculate(from: concatData, with: hmacKey, using: algorithm.ccAlgorithms.hmacAlgorithm)
        let authenticationTag = algorithm.authenticationTag(for: hmacOutput)

        return SymmetricEncryptionContext(
            ciphertext: cipherText,
            authenticationTag: authenticationTag,
            initializationVector: iv
        )
    }

    /**
     Encrypts a plain text using a given `AES` algorithm, the corresponding symmetric key and an initialization vector.
     - Parameters:
        - plaintext: The plain text to encrypt.
        - encryptionKey: The symmetric key.
        - algorithm: The algorithm used to encrypt the plain text.
        - initializationVector: The initial block.
     
     - Throws:
        - `EncryptionError.encryptingFailed(description: String)`: If the encryption failed with a specific error.
     
     - Returns: The cipher text (encrypted plain text).
     */
    func aesEncrypt(_ plaintext: Data, encryptionKey: Data, using algorithm: CCAlgorithm, and initializationVector: Data) throws -> Data {
        let dataLength = plaintext.count
        let cryptLength  = size_t(dataLength + kCCBlockSizeAES128)
        var cryptData = Data(count:cryptLength)

        let keyLength = size_t(kCCKeySizeAES256)
        let options = CCOptions(kCCOptionPKCS7Padding)

        var numBytesEncrypted: size_t = 0

        let cryptStatus = cryptData.withUnsafeMutableBytes {cryptBytes in
            plaintext.withUnsafeBytes {dataBytes in
                initializationVector.withUnsafeBytes {ivBytes in
                    encryptionKey.withUnsafeBytes {keyBytes in
                        CCCrypt(CCOperation(kCCEncrypt),
                                algorithm,
                                options,
                                keyBytes, keyLength,
                                ivBytes,
                                dataBytes, dataLength,
                                cryptBytes, cryptLength,
                                &numBytesEncrypted)
                    }
                }
            }
        }

        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.removeSubrange(numBytesEncrypted..<cryptLength)
        } else {
            throw EncryptionError.encryptingFailed(description: "Encryption failed with CryptorStatus: \(cryptStatus).")
        }

        return cryptData
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

// TODO: Delete as soon as the IV and the additionalAuthenticatedData length is calculated in a right way.
extension String {

    func hexadecimalToData() -> Data? {
        var data = Data(capacity: count / 2)

        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, range: NSMakeRange(0, utf16.count)) { match, flags, stop in
            let byteString = (self as NSString).substring(with: match!.range)
            var num = UInt8(byteString, radix: 16)!
            data.append(&num, count: 1)
        }

        guard data.count > 0 else { return nil }

        return data
    }

}
