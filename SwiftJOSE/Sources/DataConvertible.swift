//
//  DataConvertible.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 26/09/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public protocol DataConvertible {
    init?(_ data: Data)
    func data() -> Data
}
