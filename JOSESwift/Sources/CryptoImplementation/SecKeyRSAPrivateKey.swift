//
//  SecKeyRSAPublicKey.swift
//  JOSESwift
//
//  Created by Daniel Egger on 06.02.18.
//  Modified by Luke Reichold on 08.12.20
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
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

extension SecKey: ExpressibleAsRSAPrivateKeyComponents {
    public static func representing(rsaPrivateKeyComponents components: RSAPrivateKeyComponents) throws -> Self {
        return try instantiate(type: self, from: components)
    }

    // Generic helper function is needed so the compiler can infer the type of `Self`.
    private static func instantiate<T>(type: T.Type, from components: RSAPrivateKeyComponents) throws -> T {
        let keyData = try Data.representing(rsaPrivateKeyComponents: components)

        // RSA key size is the number of bits of the modulus.
        let keySize = (components.modulus.count * 8)

        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: NSNumber(value: keySize),
            kSecReturnPersistentRef: true
        ]

        var error: Unmanaged<CFError>?
        guard let keyReference = SecKeyCreateWithData(keyData as CFData,
                                                      attributes as CFDictionary,
                                                      &error) else {
            // swiftlint:disable:next force_unwrapping
            throw error!.takeRetainedValue() as Error
        }

        guard let key = keyReference as? T else {
            throw JWKError.cannotConvertToSecKeyChildClasses
        }

        return key
    }

    public func rsaPrivateKeyComponents() throws -> RSAPrivateKeyComponents {
        guard
            let attributes = SecKeyCopyAttributes(self) as? [CFString: AnyObject],
            let keyClass = attributes[kSecAttrKeyClass],
            // All possible keyClasses are of type `CFString`.
            // swiftlint:disable:next force_cast
            keyClass as! CFString == kSecAttrKeyClassPrivate
        else {
            throw JWKError.notAPrivateKey
        }

        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(self, &error) else {
            // swiftlint:disable:next force_unwrapping
            throw error!.takeRetainedValue() as Error
        }

        return try (keyData as Data).rsaPrivateKeyComponents()
    }
}
