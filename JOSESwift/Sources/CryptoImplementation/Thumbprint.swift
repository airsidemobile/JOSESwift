//
//  SHA256.swift
//  JOSESwift
//
//  Created by Thomas Torp on 08.06.20.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
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
import CommonCrypto

enum ThumbprintError: Error {
    case inputMustBeGreaterThanZero
}

fileprivate extension JWKThumbprintAlgorithm {
    var outputLenght: Int {
        switch self {
        case .SHA256:
            return Int(CC_SHA256_DIGEST_LENGTH)
        }
    }

    func calculate(input: UnsafeRawBufferPointer, output: UnsafeMutablePointer<UInt8>) {
        switch self {
        case .SHA256:
            CC_SHA256(input.baseAddress, CC_LONG(input.count), output)
        }
    }
}

internal struct Thumbprint {
    /// Calculates a hash of an input with a specific hash algorithm.
    ///
    /// - Parameters:
    ///   - input: The input to calculate a hash for.
    ///   - algorithm: The algorithm used to calculate the hash.
    /// - Returns: The calculated hash in base64URLEncoding.
    static func calculate(from input: Data, algorithm: JWKThumbprintAlgorithm) throws -> String {
        guard input.count > 0 else {
            throw ThumbprintError.inputMustBeGreaterThanZero
        }

        let hashBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: algorithm.outputLenght)
        defer { hashBytes.deallocate() }

        input.withUnsafeBytes { buffer in
            algorithm.calculate(input: buffer, output: hashBytes)
        }

        return Data(bytes: hashBytes, count: algorithm.outputLenght).base64URLEncodedString()
    }
}
