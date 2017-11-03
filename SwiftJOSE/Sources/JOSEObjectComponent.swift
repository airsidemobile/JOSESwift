//
//  JOSEObjectComponent.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 26/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public protocol JOSEObjectComponent {
    init(_ data: Data)
    func data() -> Data
}

public enum ComponentCompactSerializedIndex {
    static let jwsHeaderIndex = 0
    static let jwsPayloadIndex = 1
    static let jwsSignatureIndex = 2
    static let jweHeaderIndex = 0
    static let jweEncryptedKeyIndex = 1
    static let jweInitializationVectorIndex = 2
    static let jweCiphertextIndex = 3
    static let jweAuthenticationTagIndex = 4
}
