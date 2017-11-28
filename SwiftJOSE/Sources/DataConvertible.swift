//
//  DataConvertible.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 26/09/2017.
//

import Foundation

public protocol DataConvertible {
    init?(_ data: Data)
    func data() -> Data
}
