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
    let privateKeyTag = "com.airsidemobile.SwiftJOSE.testPrivateKey"
    var privateKey: SecKey?
    var publicKey: SecKey?
    var symmetricKey: SecKey?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        setupKeys()
        
        demoJWS()
        demoJWE()
    }
    
    func demoJWS() {
        guard publicKey != nil, privateKey != nil else {
            return
        }
        
        print("\n========== JWS ==========\n")
        print("Message:\n\(message)\n")
        
        let header = JWSHeader(algorithm: .RS512)
        let payload = JWSPayload(message.data(using: .utf8)!)
        let signer = RSASigner(key: privateKey!)
     
        var jws = JWS(header: header, payload: payload, signer: signer)
        let serialized = jws.compactSerialized
        
        print("JWS:\n\(serialized)\n")
        
        jws = try! JWS(compactSerialization: serialized)
        
        let verifier = RSAVerifier(key: publicKey!)
        if jws.validates(against: verifier) {
            print("Signature correct.")
        } else {
            print("Signature wrong")
        }
    }
    
    func demoJWE() {
        guard publicKey != nil, privateKey != nil else {
            return
        }
        
        print("\n========== JWE ==========\n")
        print("Message:\n\(message)\n")
        
        let header = JWEHeader(algorithm: .RSAOAEP, encryptionAlgorithm: .AESGCM256)
        let payload = JWEPayload(message.data(using: .utf8)!)
        let encrypter = Encrypter(keyEncryptionAlgorithm: .RSAOAEP, keyEncryptionKey: publicKey!, contentEncyptionAlgorithm: .AESGCM256, contentEncryptionKey: symmetricKey!)
        let firstJwe = JWE(header: header, payload: payload, encrypter: encrypter)
        let compactSerializationFirstJWE = firstJwe.compactSerialized
        
        print("Serialized:\n\(compactSerializationFirstJWE)\n")
        
        let secondJWE = try! JWE(compactSerialization: compactSerializationFirstJWE)
        print("Deserialized:\n\(secondJWE)\n")
        
        let decrypter = Decrypter(keyDecryptionAlgorithm: .RSAOAEP, keyDecryptionKey: privateKey!)
        if let payload = secondJWE.decrypt(with: decrypter) {
            print("Plaintext:\n\(String(data: payload.data(), encoding: .utf8)!)\n")
        }
        
        let justTheHeader = try! JOSEDeserializer().deserialize(JWEHeader.self, fromCompactSerialization: compactSerializationFirstJWE)
        print("Just The Header:\n\(justTheHeader)\n")
    }

    private func setupKeys() {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrApplicationTag as String: privateKeyTag
            ]
        ]
            
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print("\(error!)")
            return
        }
        
        privateKey = secKey
        publicKey = SecKeyCopyPublicKey(secKey)
        symmetricKey = secKey
    }
}
