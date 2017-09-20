////
////  JOSE.swift
////  SwiftJOSE
////
////  Created by Daniel Egger on 18/08/2017.
////  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
////
//
//import Foundation
//
//protocol ClaimSet: Base64URLEncodable {
//    var claims: [String: Any] { get }
//    func json() -> String?
//    func encoded() -> String
//}
//
//extension ClaimSet {
//    func json() -> String? {
//        return "JSON?(\(claims))"
//    }
//}
//
//extension ClaimSet {
//    func encoded() -> String {
//        if let jsonEncoding = json() {
//            return "Base64URL(\(jsonEncoding))"
//        }
//        
//        return "Base64URL(\(self.claims))"
//    }
//}
//
//public struct Header: ClaimSet {
//    public var claims: [String: Any]
//    
//    public init(_ claims: [String: Any]) {
//        self.claims = claims
//    }
//}
//
//public struct Payload: ClaimSet {
//    public var claims: [String: Any]
//    
//    public init(_ claims: [String: Any]) {
//        self.claims = claims
//    }
//    
//    // Other initializers may be required for claims which cannot be represented in JSON/Dictionary format
//}
//
