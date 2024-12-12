//
//  Protocol.swift
//  FlamingoCore
//
//  Created by Lee on 2024/11/22.
//

import Foundation
import CryptoKit

enum ProtocolError: Error {
    case signatureVerifyFailed
}

class Protocol {
    
    /// 构造握手请求信息
    /// - parameters:
    /// - signature:签名对象
    /// - publicKey: input message
    /// - ip: local ip address
    /// - mac: mac address
    /// - returns: Handshake data
    public static func buildHandshakeRequest(signature: Signature, publicKey: Data, ip: String, mac: Data, algorithms: Array<Algorithm>) throws -> Data {
        let salt = Data.random(length: 4)
        let hash = calculateHash(key: signature.publicKey().rawRepresentation, salt: salt)
        
        var request = Protocol_HandshakeRequest()
        request.ip = ip
        request.mac = mac
        request.publicKeyData = publicKey
        request.publicKeyHash = hash
        request.publicKeySalt = salt
        request.saltedNodeIDHash = Data()
        
        var reqAlgorithms: Array<Protocol_Algorithm> = Array()
        for a in algorithms {
            var e = Protocol_Algorithm()
            e.algorithmType = Protocol_AlgorithmType.init(rawValue: a.type.code())!
            e.speed = a.speed
            reqAlgorithms.append(e)
        }
        request.algorithms = reqAlgorithms
        
        var message = Protocol_HandshakeMessage()
        message.data = Protocol_HandshakeMessage.OneOf_Data.request(request)
        message.signature = try signature.sign(data: request.serializedData())
        
        var result = Data();
        result.append(1)
        result.append(try message.serializedData())
        return result
    }
    
    /// 解析握手响应信息
    /// - parameters:
    /// - signature:签名对象
    /// - data: Response Data
    /// - returns: Handshake response
    public static func parseHandshakeResponse(signature: Signature, data: Data) throws -> Protocol_HandshakeResponse {
        let message = try Protocol_HandshakeMessage(serializedBytes: data)
        let r = signature.verify(sign: message.signature, data: try message.response.serializedData())
        if !r {
            throw ProtocolError.signatureVerifyFailed
        }
        return message.response
    }
    
    public static func buildHeartbeatRequest() throws -> Data {
        var result = Data();
        result.append(2)
        return result
    }
    
    static func calculateHash(key: Data, salt: Data) -> Data {
        var data = Data()
        data.append(contentsOf: key)
        data.append(contentsOf: salt)
        
        let hash = SHA256.hash(data: data)
        let short_hash = hash.bytes.prefix(4)
        return Data(short_hash)
    }
}
