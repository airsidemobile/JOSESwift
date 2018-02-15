//
//  JWKSet.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 15.02.18.
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

struct JWKSet {
    let keys: [JWK]
}

extension JWKSet: Collection {
    typealias ArrayType = [JWK]

    typealias Element = ArrayType.Element
    typealias Index = ArrayType.Index
    typealias Iterator = ArrayType.Iterator

    var startIndex: Index {
        return self.keys.startIndex
    }

    var endIndex: Index {
        return self.keys.endIndex
    }

    subscript(index: Index) -> Element {
        return keys[index]
    }

    func index(after i: Index) -> Index {
        return self.keys.index(after: i)
    }

    func makeIterator() -> IndexingIterator<ArrayType> {
        return self.keys.makeIterator()
    }
}

extension JWKSet: ExpressibleByArrayLiteral {
    typealias ArrayLiteralElement = Element

    init(arrayLiteral elements: ArrayLiteralElement...) {
        var keys: [Element] = []
        for element in elements {
            keys.append(element)
        }

        self.init(keys: keys)
    }
}
