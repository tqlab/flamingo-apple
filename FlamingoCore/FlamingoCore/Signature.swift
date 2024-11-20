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
        let derivedKey = try PKCS5.PBKDF2(password: password.bytes, salt:salt.bytes, iterations: 262_144, keyLength: 32)
        let pri = try Curve25519.Signing.PrivateKey(rawRepresentation: derivedKey.calculate())
        self.privateKey = pri
    }
    
    public func sign(data: Data) throws -> Data {
        return try self.privateKey.signature(for: data)
    }
    
    public func verify(sign: Data, data: Data) ->Bool {
        return self.privateKey.publicKey.isValidSignature(sign, for: data)
    }
}
