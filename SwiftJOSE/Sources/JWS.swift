////
////  JWS.swift
////  SwiftJOSE
////
////  Created by Daniel Egger on 18/08/2017.
////  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
////
//
//import Foundation
//
//public struct JWS {
//    let header: Header
//    let payload: Payload
//    let signature: Data
//    
//    public init(header: Header, payload: Payload, signer: Signer) {
//        self.header = header
//        self.payload = payload
//        
//        let encodedHeader = self.header.encoded()
//        let encodedPayload = self.payload.encoded()
//        let signatureInput = "\(encodedHeader).\(encodedPayload)".data(using: .utf8)!
//        self.signature = signer.sign(signatureInput)
//    }
//}
//
//extension JWS: CompactSerializable {
//    public func serialized() -> String {
//        let header = self.header.encoded()
//        let payload = self.payload.encoded()
//        let signature = String(data: self.signature, encoding: .utf8)!.encoded()
//        
//        return "\(header).\(payload).\(signature)"
//    }
//}
