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

    let message = "so cool"
    let privateKey = "thePrivateKey"
    let publicKey = "thePublicKey"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        testJWS()
    }
    
    func testJWS() {
        print("Message:\n\(message)\n")
        
        let header = JWSHeader(algorithm: .rs512)
        let payload = Payload(message.data(using: .utf8)!)
        let signer = RSASigner(key: privateKey)
        let firstJWS = JWS(header: header, payload: payload, signer: signer)
        let compactSerialization = firstJWS.compactSerialized
        
        print("Serialized:\n\(compactSerialization)\n")
        
        let secondJWS = JWS(compactSerialization: compactSerialization)
        let verifier =  RSAVerifier(key: publicKey)
        if secondJWS.validates(against: verifier) {
            print("Deserialized:\n\(secondJWS)")
        }
    }

}
