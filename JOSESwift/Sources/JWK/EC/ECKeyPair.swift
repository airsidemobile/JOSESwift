//
//  ECKeyPair.swift
//  JOSESwift
//
//  Created by Mikael Rucinsky on 07.12.20.
//
//  ---------------------------------------------------------------------------
//  Copyright 2024 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import Foundation

public extension ECKeyPair {

    func getPrivate() -> ECPrivateKey {
        return self as ECPrivateKey
    }

    static func generateWith(_ curveType: ECCurveType) throws -> ECKeyPair {
        let attributes: [String: Any] = [kSecAttrKeySizeInBits as String: curveType.keyBitLength,
                                         kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                                         kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]]
        var error: Unmanaged<CFError>?
        if let ecKey: SecKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) {
            return try ECPrivateKey(privateKey: ecKey, additionalParameters: ["kid": UUID().uuidString])
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
