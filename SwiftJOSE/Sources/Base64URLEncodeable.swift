//
//  Base64URLEncodeable.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 18/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public protocol Base64URLEncodeable {
    func base64URLEncoded() -> String
}
