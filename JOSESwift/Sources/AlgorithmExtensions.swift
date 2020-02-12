//
//  AlgorithmExtensions.swift
//  JOSESwift
//
//  Created by Daniel Egger on 12.02.20.
//

import Foundation

extension ContentEncryptionAlgorithm {
    var hmacAlgorithm: HMACAlgorithm {
           switch self {
           case .A256CBCHS512:
               return .SHA512
           case .A128CBCHS256:
               return .SHA256
           }
       }

       var keyLength: Int {
           switch self {
           case .A256CBCHS512:
               return 64
           case .A128CBCHS256:
               return 32
           }
       }

       var initializationVectorLength: Int {
           switch self {
           case .A256CBCHS512:
               return 16
           case .A128CBCHS256:
               return 16
           }
       }

       func checkKeyLength(for key: Data) -> Bool {
           switch self {
           case .A256CBCHS512:
               return key.count == 64
           case .A128CBCHS256:
               return key.count == 32
           }
       }

       func retrieveKeys(from inputKey: Data) throws -> (hmacKey: Data, encryptionKey: Data) {
           switch self {
           case .A256CBCHS512:
               guard checkKeyLength(for: inputKey) else {
                   throw JWEError.keyLengthNotSatisfied
               }

               return (inputKey.subdata(in: 0..<32), inputKey.subdata(in: 32..<64))

           case .A128CBCHS256:
               guard checkKeyLength(for: inputKey) else {
                   throw JWEError.keyLengthNotSatisfied
               }
               return (inputKey.subdata(in: 0..<16), inputKey.subdata(in: 16..<32))
           }
       }

       func authenticationTag(for hmac: Data) -> Data {
           switch self {
           case .A256CBCHS512:
               return hmac.subdata(in: 0..<32)
           case .A128CBCHS256:
               return hmac.subdata(in: 0..<16)
           }
       }
}
