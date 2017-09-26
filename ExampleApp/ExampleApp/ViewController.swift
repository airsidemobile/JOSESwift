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
        let header = Header(["gnu": "linux"])
        let payload = Payload("so cool".data(using: .utf8)!)
        let signer = RSASigner(algorithm: .rs512, key: "signingKey")
        let jws = JWS(header: header, payload: payload, signer: signer)
        
        let compactSerialization = CompactSerializer().serialize(jws)
        
        print("=== COMAPCT SERIALIZED ===")
        print(compactSerialization)
    }
    
    func testJWSDecoding() {
        let compactSerialization = "eyJkdW1teSI6ICJoZWFkZXIifQ==.eyJkdW1teSI6InBheWxvYWQifQ==.ZHVtbXlzaWduYXR1cmU="
        let jws = CompactDeserializer().deserialize(JWS.self, from: compactSerialization)
        
        print("=== COMPACT DESERIALIZED ===")
        print("\(jws.header) \(String(data: jws.payload.data(), encoding: .utf8)!) \(String(data: jws.signature.data(), encoding: .utf8)!)")
    }

}
