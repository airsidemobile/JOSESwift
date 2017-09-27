//
//  ViewController.swift
//  ExampleApp
//
//  Created by Daniel Egger on 17/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import UIKit
@testable import SwiftJOSE

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        testJWSEncoding()
        print()
        testJWSDecoding()
    }
    
    func testJWSEncoding() {
        let header = JWSHeader(algorithm: .rs512)
        let payload = Payload("dummy payload".data(using: .utf8)!)
        let signer = RSASigner(publicKey: "theKey")
        let jws = JWS(header: header, payload: payload, signer: signer)
        let compactSerialization = Serializer().compact(jws)
        
        print("=== COMPACT SERIALIZED ===")
        print(compactSerialization)
    }
    
    func testJWSDecoding() {
        let compactSerialization = "eyJkdW1teSI6ImhlYWRlciJ9.ZHVtbXkgcGF5bG9hZA==.ZHVtbXkgc2lnbmF0dXJl"
        let jws = Deserializer().deserialize(JWS.self, fromCompactSerialization: compactSerialization)
        let verifier = RSAVerifier(algorithm: .rs512, key: "publicKey")
        
        guard jws.validates(against: verifier) else {
            return
        }
        
        print("=== COMPACT DESERIALIZED ===")
        print("\(jws.header)\n\(String(data: jws.payload.data(), encoding: .utf8)!)\n\(String(data: jws.signature.data(), encoding: .utf8)!)")
    }

}
