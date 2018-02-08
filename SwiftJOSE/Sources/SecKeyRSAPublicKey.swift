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
    public static func converted(from components: RSAPublicKeyComponents) -> Self? {
        return instantiate(self, from: components)
    }

    private static func instantiate<T>(_ type: T.Type, from components: RSAPublicKeyComponents) -> T? {
        return nil
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
