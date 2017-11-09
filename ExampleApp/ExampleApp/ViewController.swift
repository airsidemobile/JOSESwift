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

    let message = "The true sign of intelligence is not knowledge but imagination."
    let privateKey = "thePrivateKey"
    let publicKey = "thePublicKey"
    let sharedKey = "sharedKey"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        demoJWS()
        demoJWE()
    }
    
    func demoJWS() {
        print("\n========== JWS ==========\n")
        print("Message:\n\(message)\n")
        
        let header = JWSHeader(algorithm: .RS512)
        let payload = JWSPayload(message.data(using: .utf8)!)
        let signer = RSASigner(key: privateKey)
        let firstJWS = JWS(header: header, payload: payload, signer: signer)
        let compactSerializationFirstJWS = firstJWS.compactSerialized
        
        print("Serialized:\n\(compactSerializationFirstJWS)\n")
        
        let secondJWS = JWS(compactSerialization: compactSerializationFirstJWS)
        let verifier =  RSAVerifier(key: publicKey)
        if secondJWS.validates(against: verifier) {
            print("Deserialized:\n\(secondJWS)\n")
        }
        
        let justTheHeader = JOSEDeserializer().deserialize(JWSHeader.self, fromCompactSerialization: compactSerializationFirstJWS)
        print("Just The Header:\n\(justTheHeader)\n")
        let justThePayload = JOSEDeserializer().deserialize(JWSPayload.self, fromCompactSerialization: compactSerializationFirstJWS)
        print("Just The Payload:\n\(justThePayload)")
    }
    
    func demoJWE() {
        print("\n========== JWE ==========\n")
        print("Message:\n\(message)\n")
        
        let header = JWEHeader(algorithm: .RSAOAEP, encryptionAlgorithm: .AESGCM256)
        let payload = JWEPayload(message.data(using: .utf8)!)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .RSAOAEP, keyEncryptionKey: publicKey.data(using: .utf8)!, contentEncyptionAlgorithm: .AESGCM256, contentEncryptionKey: sharedKey.data(using: .utf8)!)
        let firstJwe = JWE(header: header, payload: payload, encrypter: encrypter)
        let compactSerializationFirstJWE = firstJwe.compactSerialized
        
        print("Serialized:\n\(compactSerializationFirstJWE)\n")
        
        let secondJWE = JWE(compactSerialization: compactSerializationFirstJWE)
        print("Deserialized:\n\(secondJWE)\n")
        
        let decrypter = Decrypter(keyDecryptionAlgorithm: .RSAOAEP, keyDecryptionKey: "privateKey".data(using: .utf8)!)
        if let payload = secondJWE.decrypt(with: decrypter) {
            print("Plaintext:\n\(String(data: payload.data(), encoding: .utf8)!)\n")
        }
        
        let justTheHeader = JOSEDeserializer().deserialize(JWEHeader.self, fromCompactSerialization: compactSerializationFirstJWE)
        print("Just The Header:\n\(justTheHeader)\n")
    }

}
