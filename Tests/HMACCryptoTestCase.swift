// swiftlint:disable force_unwrapping
//
//  HMACCryptoTestCase.swift
//  Tests
//
//  Created by Tobias Hagemann on 14.04.21.
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

import XCTest

/// Test data provided in the [RFC-4231](https://tools.ietf.org/html/rfc4231).
/// Compact serialization generated at [jwt.io](https://jwt.io)
class HMACCryptoTestCase: CryptoTestCase {
    let testKey = "0102030405060708090a0b0c0d0e0f10111213141516171819".hexadecimalToData()!
    let testData = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".hexadecimalToData()!
    let hmac256TestOutput = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b".hexadecimalToData()!
    let hmac384TestOutput = "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb".hexadecimalToData()!
    let hmac512TestOutput = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd".hexadecimalToData()!

    let compactSerializedJWSHS256Const =
        """
        eyJhbGciOiJIUzI1NiJ9\
        .\
        VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\
        .\
        Fw75Z9cJ6lV-uPrZOrN2CLXquucZ00VQit7F_PTWFUs
        """
    let compactSerializedJWSHS384Const =
        """
        eyJhbGciOiJIUzM4NCJ9\
        .\
        VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\
        .\
        H08sUX3X4bkhz0TvtJ9tAVWPeyiXZsickDSTaR7GRGstKWetstGuMgyfHvBT11vw
        """
    let compactSerializedJWSHS512Const =
        """
        eyJhbGciOiJIUzUxMiJ9\
        .\
        VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\
        .\
        bCJ58-nDpVQkpz7ftEpnOr5h6mcZeO27_j2NAzFK6fDNnKv7l54_gIs62MdAWg1DnDB21RsMDQJr7G4HFYr1nw
        """
    let signingKey = Data(base64URLEncoded:
        """
        AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow
        """
    )!

    override func setupKeys() {
        // do nothing
    }
}
// swiftlint:enable force_unwrapping
