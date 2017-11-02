//
//  Algorithm.swift
//  SwiftJOSE
//
//  Created by Daniel Egger on 12/10/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import Foundation

public enum Algorithm: String {
    case RS512 = "RS512"
    case RSAOAEP = "RSA-OAEP"
    case AESGCM256 = "A256GCM"
}
