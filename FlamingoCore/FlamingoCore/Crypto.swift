//
//  Crypto.swift
//  FlamingoCore
//
//  Created by Lee on 2024/11/20.
//
import CryptoKit

public enum AlgorithmType: CaseIterable, Hashable {
    case AES_GCM_128
    case AES_GCM_256
    case CHACHA20_POLY1305
}

public enum CryptoError: Error {
    case DecryptError
}

public class Crypto {
    
    private let privateKey: Curve25519.KeyAgreement.PrivateKey
    private let algorithmType: AlgorithmType
    /// Peer public key
    private let publicKey: Curve25519.KeyAgreement.PublicKey
    private let symmetricKey: SymmetricKey
    
    init(privateKey: Curve25519.KeyAgreement.PrivateKey, algorithmType: AlgorithmType, publicKey: Data) throws {
        self.privateKey = privateKey
        self.algorithmType = algorithmType
        
        let peerPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        self.publicKey = peerPublicKey
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
        nonceData.append(contentsOf: extra[1..<8])
        
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
}
