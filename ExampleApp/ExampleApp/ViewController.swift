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
        var jws = JWS(header: Header(["foo" : "bar"]), payload: Payload(["bing": "bong"]))
        let signer =  Signer(algorithm: .rs512, key: "dummyPrivateKey")
        
        jws.sign(using: signer)
        
        print(jws.serialize())
    }

}
