//
//  SecKeyRSAPublicKey.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 06.02.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
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
import Security

extension SecKey: ExpressibleAsRSAPublicKeyComponents {
    public static func converted(from components: RSAPublicKeyComponents) throws -> Self {
        return try instantiate(self, from: components)
    }

    private static func instantiate<T>(_ type: T.Type, from components: RSAPublicKeyComponents) throws -> T {
        let keyData = try Data.converted(from: components)

        // RSA key size is the number of bits of the modulus.
        let keySize = (components.modulus.count * 8)

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String : keySize,
            kSecAttrIsPermanent as String: false
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        guard let ret = key as? T else {
            throw JWKError.notASecKey(description:
                "You need to convert RSAPublicKeyComponents directly to a `SecKey` not a subclass of it."
            )
        }

        return ret
    }

    public func rsaPublicKeyComponents() throws -> RSAPublicKeyComponents {
        guard
            let attributes = SecKeyCopyAttributes(self) as? [CFString: AnyObject],
            let keyClass = attributes[kSecAttrKeyClass],
            // All possible keyClasses are of type `CFString`.
            // swiftlint:disable:next force_cast
            keyClass as! CFString == kSecAttrKeyClassPublic
        else {
            throw JWKError.notAPublicKey
        }

        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(self, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        return try (keyData as Data).rsaPublicKeyComponents()
    }
}
