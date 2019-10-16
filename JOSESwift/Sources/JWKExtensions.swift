//
//  JWKExtensions.swift
//  JOSESwift
//
//  Created by Daniel Egger on 21.12.17.
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

// MARK: Subscript

public extension JWK {
    subscript(parameter: String) -> String? {
        return parameters[parameter]
    }
}

// MARK: Encoding Convenience Functions

public extension JWK {
    func jsonString() -> String? {
        guard let json = try? JSONEncoder().encode(self) else {
            return nil
        }

        return String(data: json, encoding: .utf8)
    }

    func jsonData() -> Data? {
        return try? JSONEncoder().encode(self)
    }
}
