//
//  ECKeyPair.swift
//  JOSESwift
//
//  Created by Mikael Rucinsky on 07.12.20.
//

import Foundation

// MARK: Key Pair

public extension ECKeyPair {

    func getPrivate() -> ECPrivateKey {
        return self as ECPrivateKey
    }

    static func generateWith(_ curveType: ECCurveType) throws -> ECKeyPair {
        let attributes: [String: Any] = [kSecAttrKeySizeInBits as String: curveType.keyBitLength,
                                         kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                                         kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]]
        var error: Unmanaged<CFError>?
        if let eckey: SecKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) {
            return try ECPrivateKey(privateKey: eckey, additionalParameters: ["kid": UUID().uuidString])
        }
        throw ECKeyPairError.generateECKeyPairFail
    }
}

public extension ECPrivateKey {

    func getPublic() -> ECPublicKey {
        let parametersForPublic = parameters.filter { $0.key != ECParameter.privateKey.rawValue }
        return ECPublicKey(crv: crv, x: x, y: y, additionalParameters: parametersForPublic)
    }

    func isCorrespondWith(_ key: ECPublicKey) -> Bool {
        guard
            crv == key.crv,
            x == key.x,
            y == key.y
        else {
            return false
        }
        return true
    }
}

public enum ECKeyPairError: Error {
    case generateECKeyPairFail
}
