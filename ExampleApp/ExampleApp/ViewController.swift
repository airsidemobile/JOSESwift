//
//  ViewController.swift
//  ExampleApp
//
//  Created by Daniel Egger on 17/08/2017.
//  Copyright © 2017 Airside Mobile, Inc. All rights reserved.
//

import UIKit
import SwiftJOSE

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        testJWS()
    }
    
    func testJWS() {
        let signer = RSASigner(algorithm: .rs512, key: "signingKey")
        let jws = JWS(header: Header(["gnu": "linux"]), payload: Payload(["so": "cool"]), signer: signer)
        let compactSerialization = jws.compactSerialization()
        
        print(compactSerialization)
    }

}
