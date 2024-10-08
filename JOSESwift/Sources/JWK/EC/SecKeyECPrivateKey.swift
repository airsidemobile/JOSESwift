//
//  SecKeyECPrivateKey.swift
//  JOSESwift
//
//  Created by Jarrod Moldrich on 10.01.2019.
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
////

import Foundation
import Security

extension SecKey: ExpressibleAsECPrivateKeyComponents {
    public static func representing(ecPrivateKeyComponents components: ECPrivateKeyComponents) throws -> Self {
        return try instantiate(type: self, from: components)
    }

    // Generic helper function is needed so the compiler can infer the type of `Self`.
    private static func instantiate<T>(type: T.Type, from components: ECPrivateKeyComponents) throws -> T {
        let keyData = try Data.representing(ecPrivateKeyComponents: components)

        guard
                let keySize = ECCurveType(rawValue: components.crv)?.keyBitLength
                else {
            throw JWKError.invalidECCurveType
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: keySize,
            kSecAttrIsPermanent as String: false
        ]

        var error: Unmanaged<CFError>?
        guard let keyReference = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            // swiftlint:disable:next force_unwrapping
            throw error!.takeRetainedValue() as Error
        }

        guard let key = keyReference as? T else {
            throw JWKError.cannotConvertToSecKeyChildClasses
        }

        return key
    }

    public func ecPrivateKeyComponents() throws -> ECPrivateKeyComponents {
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

        return try (keyData as Data).ecPrivateKeyComponents()
    }
}
