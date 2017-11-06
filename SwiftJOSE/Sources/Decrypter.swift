//
//  Decrypter.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 17/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public protocol Decrypter {
    init(privateKey kdk: String)
    func decrypt(ciphertext: Data, with header: JWEHeader, and additionalInformation: JWEAdditionalCryptoInformation) -> Data?
}
