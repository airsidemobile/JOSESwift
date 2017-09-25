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
        testJWSDecoding()
    }
    
    func testJWSEncoding() {
        let header = Header(["gnu": "linux"])
        let payload = Payload("so cool".data(using: .utf8)!)
        let signer = RSASigner(algorithm: .rs512, key: "signingKey")
        let jws = JWS(header: header, payload: payload, signer: signer)
        
        print(jws.compactSerialization())
    }
    
    func testJWSDecoding() {
        let compactSerialization = "eyJkdW1teSI6ICJoZWFkZXIifQ==.eyJkdW1teSI6InBheWxvYWQifQ==.ZHVtbXlzaWduYXR1cmU="
        let jws = CompactDeserializer().deserialize(JWS.self, from: compactSerialization)
        
        print(jws)
    }

}
