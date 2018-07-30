//
//  SecureRandom.swift
//  JOSESwift
//
//  Created by Carol Capek on 07.12.17.
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

public enum SecureRandomError: Error {
    case failed(status: OSStatus)
}

public struct SecureRandom {
    /// Generates secure random data with a given count.
    ///
    /// - Parameter count: The count of the random generated data.
    /// - Returns: The random generated data.
    /// - Throws: `SecureRandomError` if any error occurs during generation of secure random bytes. 
    public static func generate(count: Int) throws -> Data {
        var generatedRandom = Data(count: count)

        let randomGenerationStatus = generatedRandom.withUnsafeMutableBytes { mutableRandomBytes in
            SecRandomCopyBytes(kSecRandomDefault, count, mutableRandomBytes)
        }

        guard randomGenerationStatus == errSecSuccess else {
            throw SecureRandomError.failed(status: randomGenerationStatus)
        }

        return generatedRandom
    }
}
