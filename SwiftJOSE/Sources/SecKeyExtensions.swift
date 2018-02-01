//
//  SecKeyExtensions.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 14.12.17.
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

extension SecKey: RSAPublicKeyConvertible {
    public var modulus: Data? {
        return "MODULUS".data(using: .utf8)
    }

    public var publicExponent: Data? {
        return "EXPONENT".data(using: .utf8)
    }
}

extension SecKey: RSAPrivateKeyConvertible {
    public var privateExponent: Data? {
        return "PRIVATE_EXPONENT".data(using: .utf8)
    }
}

extension JWK {
    static func secKeyRepresentation() throws -> SecKey {
        // Todo: Do conversion from JWK modulus/exponent representation to SecKey.
        // Todo: Decide on exact control flow.
        // See https://mohemian.atlassian.net/browse/JOSE-92.
        // See https://github.com/henrinormak/Heimdall/blob/master/Heimdall/Heimdall.swift.

        var item: CFTypeRef?
        // This is just a mock will be deleted in the implementation story.
        // swiftlint:disable:next force_cast
        return item as! SecKey
    }
}
