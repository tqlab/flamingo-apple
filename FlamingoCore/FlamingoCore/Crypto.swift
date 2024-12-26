//
//  Crypto.swift
//  FlamingoCore
//
//  Created by Lee on 2024/11/20.
//
import CryptoKit
import Foundation

public enum AlgorithmType: CaseIterable, Hashable {
    case AES_GCM_128
    case AES_GCM_256
    case CHACHA20_POLY1305
    
    public func code()->Int {
        switch self {
        case .AES_GCM_128:
            return 0
        case .AES_GCM_256:
            return 1
        case .CHACHA20_POLY1305:
            return 2
        }
    }
    
    public static func fromCode(code: Int) -> AlgorithmType? {
        switch code {
        case 0:
            return AlgorithmType.AES_GCM_128
        case 1:
            return AlgorithmType.AES_GCM_256
        case 2:
            return AlgorithmType.CHACHA20_POLY1305
        default:
            return nil
        }
    }
    
    public func toString() -> String {
        switch self {
        case .AES_GCM_128:
            return "AES_GCM_128"
        case .AES_GCM_256:
            return "AES_GCM_256"
        case .CHACHA20_POLY1305:
            return "CHACHA20_POLY1305"
        }
    }
}

public struct Algorithm {
    var type: AlgorithmType
    var speed: Float
}

public enum CryptoError: Error {
    case DecryptError
}

public class Crypto {
    
    private let algorithmType: AlgorithmType
    private let symmetricKey: SymmetricKey
    
    init(privateKey: Curve25519.KeyAgreement.PrivateKey, algorithmType: AlgorithmType, publicKey: Data) throws {
        self.algorithmType = algorithmType
        
        let peerPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        self.symmetricKey = try Crypto.deriveKey(privateKey: privateKey, publicKey: peerPublicKey, algorithmType: algorithmType)
    }
    
    public func encrypt(data: Data) throws -> Data {
        var nonceData = Data()
        nonceData.append(contentsOf: [0,0,0,0,0])
        var extraData = Data()
        extraData.append(0)
        
        switch self.algorithmType {
        case .AES_GCM_128, .AES_GCM_256:
            AES.GCM.Nonce().withUnsafeBytes { (nonceBytes: UnsafeRawBufferPointer) in
                let subBytes = nonceBytes.suffix(7)
                nonceData.append(contentsOf: subBytes)
                extraData.append(contentsOf: subBytes)
            }
            
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.seal(data, using: self.symmetricKey, nonce: nonce)
            var combined = Data(extraData.bytes)
            combined.append(sealedBox.ciphertext)
            combined.append(sealedBox.tag)
            return combined
        case .CHACHA20_POLY1305:
            ChaChaPoly.Nonce().withUnsafeBytes { (nonceBytes: UnsafeRawBufferPointer) in
                let subBytes = nonceBytes.suffix(7)
                nonceData.append(contentsOf: subBytes)
                extraData.append(contentsOf: subBytes)
            }
            
            let nonce = try ChaChaPoly.Nonce(data: nonceData)
            let sealedBox = try ChaChaPoly.seal(data, using: self.symmetricKey, nonce: nonce)
            var combined = Data(extraData.bytes)
            combined.append(sealedBox.ciphertext)
            combined.append(sealedBox.tag)
            return combined
        }
    }
    
    public func decrypt(data: Data) throws -> Data {
        if data.count < 24 {
            throw CryptoError.DecryptError
        }
        let extra = data.prefix(8)
        let ciphertextAndTag = data.suffix(data.count-8)
        let ciphertext = ciphertextAndTag.prefix(ciphertextAndTag.count - 16)
        let tag = ciphertextAndTag.suffix(16)
        
        var nonceData = Data()
        nonceData.append(contentsOf: [0,0,0,0,0])
        nonceData.append(contentsOf: extra.suffix(7))
        
        switch self.algorithmType {
        case .AES_GCM_128, .AES_GCM_256:
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            let plainText = try AES.GCM.open(sealedBox, using: self.symmetricKey)
            return plainText
        case .CHACHA20_POLY1305:
            let nonce = try ChaChaPoly.Nonce(data: nonceData)
            let sealedBox = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            let plainText = try ChaChaPoly.open(sealedBox, using: self.symmetricKey)
            return plainText
        }
        
    }
    
    fileprivate static func deriveKey(privateKey: Curve25519.KeyAgreement.PrivateKey,  publicKey: Curve25519.KeyAgreement.PublicKey, algorithmType: AlgorithmType) throws -> SymmetricKey {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        switch algorithmType {
        case .AES_GCM_128:
            return SymmetricKey(data: sharedSecret.bytes.prefix(16))
        case .AES_GCM_256, .CHACHA20_POLY1305:
            return SymmetricKey(data: sharedSecret.bytes)
        }
    }
    
    public static func createEcdhKeypair()-> Curve25519.KeyAgreement.PrivateKey {
        return Curve25519.KeyAgreement.PrivateKey()
    }
    
    ///
    /// 加密算法测速
    ///
    public static func testSpeed(algorithmType: AlgorithmType, maxNanoTime: UInt64) throws -> Float {
        let priKey1 = Crypto.createEcdhKeypair()
        let priKey2 = Crypto.createEcdhKeypair()
        
        let sender = try Crypto(privateKey: priKey1, algorithmType: algorithmType, publicKey: priKey2.publicKey.rawRepresentation)
        let receiver = try Crypto(privateKey: priKey2, algorithmType: algorithmType, publicKey: priKey1.publicKey.rawRepresentation)
        let data = Data.random(length: 1024)
        
        let start = DispatchTime.now()
        
        var total = 10000
        while(total > 0 ) {
            for _ in (0 ... 1000) {
                let e = try sender.encrypt(data: data)
                let _ = try receiver.decrypt(data: e)
            }
            total -= 1000
        }
        let end = DispatchTime.now()
        
        let duration: Double = Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000_000.0
        return Float(Double(10000 * 2 * 1024) / duration / (1024 * 1024))
    }
}
