//
//  CompactSerializable.swift
//  SwiftJOSE
//
//  Created by Daniel on 21/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public protocol CompactSerializable {
    func compactSerialization() -> String
}

