//
//  encrypt.swift
//  encrypt
//
//  Created by John Woods on 26/02/2020.
//  Copyright © 2020 John Woods. All rights reserved.
//

// frameworks
import Foundation
import Sodium

// extension for tilde expansion
extension String {
    var expandingTildeInPath: String {
        return NSString(string: self).expandingTildeInPath
    }
}

// extension for hex manipulation
extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }

    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return map { String(format: format, $0) }.joined()
    }
}

// extension for [byte] to data
extension Array where Element == UInt8 {
    var data : Data{
        return Data(self)
    }
}

// extension for data to [byte]]
extension Data {
    var bytes : [UInt8]{
        return [UInt8](self)
    }
}


class FileProcessor {
    var target: Data? = nil
    var dataFileURLString = ""
    let sodiumContext = Sodium()

    func read() -> () {
        
        let cryptoCore = CryptoCore(fileProcessor: self)
        if(CommandLine.arguments.count == 2) {
            self.dataFileURLString = CommandLine.arguments[1].expandingTildeInPath
            let inputDataFileURL = URL(fileURLWithPath: dataFileURLString)
            do {
                let data = try Data(contentsOf: inputDataFileURL)
                self.target = data
                
                if(self.target?.bytes.count ?? 0 > 32) {
                    let potentialHash = Array<UInt8>(self.target?.bytes.suffix(from: (self.target?.bytes.count ?? 0)-32) ?? [])
                    if(potentialHash.data.hexEncodedString() == self.sodiumContext.genericHash.hash(message: Array<UInt8>(self.target?.bytes.prefix(upTo: self.target!.bytes.count-32) ?? []), outputLength: 32)!.data.hexEncodedString()) {
                        
                        print("encrypt: encrypted data found, decrypting")
                        
                        self.target = Array<UInt8>(self.target!.bytes.prefix(upTo: self.target!.bytes.count-32)).data
                        cryptoCore.dec()
                        
                    } else {
                        print("encrypt: unencrypted data found, encrypting")
                        cryptoCore.enc()

                    }
                } else {
                    print("encrypt: unencrypted data found, encrypting")
                    cryptoCore.enc()

                }
                  
            } catch {
                print("encrypt: please specify a single file to process")
                // Handle the error
            }
        } else {
            //bad number of arguments, printing help
            print("encrypt - easy file (en/de)cryption.\n\nusage:\n./encrypt someFile\n\nencrypt will know if a file needs to be encrypted or decrypted automatically.\n\nencrypt uses 256-bit keys with salted Xsalsa20+Poly1305 & Argon2 password based key derivation")
        }
    }
    
    
    func write(data:Data, encrypted:Bool) -> () {
        
        self.target = data
        var outputDataFileURL:URL? = nil
        if(encrypted) {
            outputDataFileURL = URL(fileURLWithPath: self.dataFileURLString+".xsalsa20poly1305")
            print("encrypt: encrypt done, writing encrypted file to \(outputDataFileURL?.absoluteString ?? "error")")

        } else {
            outputDataFileURL = URL(fileURLWithPath: String(self.dataFileURLString.dropLast(17)))
            print("encrypt: decrypt done, writing decrypted file to \(outputDataFileURL?.absoluteString ?? "error")")
        }
        do {
            try self.target?.write(to: outputDataFileURL!)
        } catch {
            print("encrypt: could not write file")
        }
    }
    
}


class CryptoCore {
    let sodiumContext = Sodium()
    var fileProcessorContext: FileProcessor
    
    init(fileProcessor:FileProcessor) {
        self.fileProcessorContext = fileProcessor
    }
  
    func enc() -> () {

        let salt = sodiumContext.randomBytes.buf(length: 16)!
        var password:String? = String(validatingUTF8: UnsafePointer<CChar>(getpass("encrypt: enter password to derive encryption key:")))

        if(password != nil) {
            let key = sodiumContext.pwHash.hash(outputLength: 32, passwd: password!.bytes, salt: salt, opsLimit: sodiumContext.pwHash.OpsLimitSensitive, memLimit: sodiumContext.pwHash.MemLimitSensitive)
            
            password = nil;

            var symmetricKey: SecretBox.Key = key!
            let encryptedBytes: Bytes = sodiumContext.secretBox.seal(message: self.fileProcessorContext.target!.bytes, secretKey: symmetricKey)!
            
            var outputData = encryptedBytes.data
            outputData.append(salt.data)
            outputData.append(sodiumContext.genericHash.hash(message: outputData.bytes, outputLength: 32)!.data)
            self.fileProcessorContext.write(data: outputData, encrypted: true)
        
            self.fileProcessorContext.target = nil
            sodiumContext.utils.zero(&symmetricKey)
        }



        //zero mem
        //check key
        //check lib cipher
        //audit
        //contribute to docs on pwhash for swift sodium
        //clean up references between classes, and cryptocore as property.
        
    }
    
    
    func dec() -> () {
        if(CommandLine.arguments.count == 2) {
            let salt = Array(self.fileProcessorContext.target!.bytes.suffix(from: self.fileProcessorContext.target!.bytes.count-16))
            let payload = Array(self.fileProcessorContext.target!.bytes.prefix(upTo: self.fileProcessorContext.target!.bytes.count-16))
                
            var password:String? = String(validatingUTF8: UnsafePointer<CChar>(getpass("encrypt: enter password to derive decryption key:")))

            if(password != nil) {
                let key = sodiumContext.pwHash.hash(outputLength: 32, passwd: password!.bytes, salt: salt, opsLimit: sodiumContext.pwHash.OpsLimitSensitive, memLimit: sodiumContext.pwHash.MemLimitSensitive)
                
                password = nil;

                var symmetricKey: SecretBox.Key = key!

                var decrypted:Bytes? = sodiumContext.secretBox.open(nonceAndAuthenticatedCipherText: payload, secretKey: symmetricKey)
                if(decrypted != nil) {
                    sodiumContext.utils.zero(&symmetricKey)
                    self.fileProcessorContext.write(data: decrypted!.data, encrypted: false)
                    decrypted = nil
                    
                } else {
                    sodiumContext.utils.zero(&symmetricKey)
                    print("encrypt: could not decrypt, bad password or file")
                }
            }
            

        }
        else {
                print("encrypt - easy file (en/de)cryption.\n\nusage:\n./encrypt someFile\n\nencrypt will know if a file needs to be encrypted or decrypted automatically.\n\nencrypt uses 256-bit keys with salted Xsalsa20+Poly1305 & Argon2 password based key derivation")
        }
    }
}
