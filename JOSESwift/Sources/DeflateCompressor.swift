//
//  DeflateCompressor.swift
//  JOSESwift
//
//  Created by Florian Häser on 24.12.18.
//

import Foundation

internal protocol DeflateCompressor {
    func deflate() -> Data?
    func inflate() -> Data?
}
