//
//  SecKeyJWKBuilder.swift
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

public class SecKeyJWKBuilder: JWKBuilder {
    typealias KeyDataType = SecKey

    private var publicKey: SecKey?
    private var privateKey: SecKey?
    private var parameters: [String: Any] = [:]

    public init() { }

    public func set(publicKey: SecKey) -> Self {
        self.publicKey = publicKey
        return self
    }

    public func set(privateKey: SecKey) -> Self {
        self.privateKey = privateKey
        return self
    }

    public func set(_ parameter: String, to value: Any) -> Self {
        parameters[parameter] = value
        return self
    }

    public func build() -> JWK? {
        // Todo: Impove before implementation https://mohemian.atlassian.net/browse/JOSE-94.

        // Todo: Do conversion from SecKey representation to JWK modulus/exponent.
        // See https://mohemian.atlassian.net/browse/JOSE-91.
        // See https://github.com/henrinormak/Heimdall/blob/master/Heimdall/Heimdall.swift.

        // Only public key set
        if (publicKey != nil) && (privateKey == nil) {
            return RSAPublicKey(modulus: "0vx...Kgw", exponent: "AQAB", additionalParameters: parameters)
        }

        // Private key set.
        // We don't care about the public key at this point since it is contained in the private key.
        if privateKey != nil {
            return RSAPrivateKey(modulus: "0vx...Kgw", exponent: "AQAB", privateExponent: "X4c...C8Q", additionalParameters: parameters)
        }

        // No keys set
        return nil
    }
}

extension JWK {
    // Todo: Improve before implementation https://mohemian.atlassian.net/browse/JOSE-94.
    static func secKeyRepresentation() throws -> SecKey {
        // Todo: Do conversion from JWK modulus/exponent representation to SecKey.
        // See https://mohemian.atlassian.net/browse/JOSE-92.
        // See https://github.com/henrinormak/Heimdall/blob/master/Heimdall/Heimdall.swift.

        var item: CFTypeRef?
        // This is just a mock will be deleted in the implementation story.
        // swiftlint:disable:next force_cast
        return item as! SecKey
    }
}
