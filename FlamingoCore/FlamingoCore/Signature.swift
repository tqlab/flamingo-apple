//
//  Signature.swift
//  FlamingoCore
//
//  Created by Lee on 2024/11/20.
//
import CryptoKit
import Foundation
internal import CryptoSwift

public class Signature {
    private let salt = "flamingoflamiNGOFlamingoflamingo"
    private let privateKey: Curve25519.Signing.PrivateKey
    
    public init(password: String) throws {
        let derivedKey = try PKCS5.PBKDF2(password: password.bytes, salt:salt.bytes, iterations: /*262_144*/4096, keyLength: 32)
        let pri = try Curve25519.Signing.PrivateKey(rawRepresentation: derivedKey.calculate())
        self.privateKey = pri
    }
    
    public func sign(data: Data) throws -> Data {
        return try self.privateKey.signature(for: data)
    }
    
    public func verify(public_key_salt: Data, public_key_hash: Data, sign: Data, data: Data) ->Bool {
        let public_key = publicKey().rawRepresentation
        let hash = Signature.calculateHash(key: public_key, salt: public_key_salt)
        if hash != public_key_hash {
            return false;
        }

        return self.privateKey.publicKey.isValidSignature(sign, for: data)
    }
    
    public func publicKey() -> Curve25519.Signing.PublicKey {
        return self.privateKey.publicKey
    }
    
    public static func calculateHash(key: Data, salt: Data) -> Data {
        var data = Data()
        data.append(contentsOf: key)
        data.append(contentsOf: salt)
        
        let hash = SHA256.hash(data: data)
        let short_hash = hash.bytes.prefix(4)
        return Data(short_hash)
    }
}
