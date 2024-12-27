//
//  Protocol.swift
//  FlamingoCore
//
//  Created by Lee on 2024/11/22.
//

import CryptoKit
import Foundation

enum ProtocolError: Error {
    case signatureVerifyFailed
}

class Protocol {

    /// 构造握手请求信息
    /// - parameters:
    /// - signature:签名对象
    /// - id: peer id
    /// - publicKey: input message
    /// - ip: local ip address
    /// - mac: mac address
    /// - returns: Handshake data
    public static func buildHandshakeRequest(
        signature: Signature, id: PeerId, publicKey: Data,
        algorithms: [Algorithm]
    ) throws -> Data {
        let salt = Data.random(length: 4)
        let hash = Signature.calculateHash(
            key: signature.publicKey().rawRepresentation, salt: salt)

        var request = Protocol_HandshakeRequest()
        request.id = id.id
        request.publicKeyData = publicKey
        request.publicKeyHash = hash
        request.publicKeySalt = salt

        var reqAlgorithms: [Protocol_Algorithm] = Array()
        for a in algorithms {
            var e = Protocol_Algorithm()
            e.algorithmType = Protocol_AlgorithmType.init(
                rawValue: a.type.code())!
            e.speed = a.speed
            reqAlgorithms.append(e)
        }
        request.algorithms = reqAlgorithms

        var message = Protocol_HandshakeMessage()
        message.data = Protocol_HandshakeMessage.OneOf_Data.request(request)
        message.signature = try signature.sign(data: request.serializedData())

        var result = Data()
        result.append(1)
        result.append(try message.serializedData())
        return result
    }

    /// 解析握手响应信息
    /// - parameters:
    /// - signature:签名对象
    /// - data: Response Data
    /// - returns: Handshake response
    public static func parseHandshakeResponse(signature: Signature, data: Data)
        throws -> Protocol_HandshakeResponse
    {
        let message = try Protocol_HandshakeMessage(serializedBytes: data)
        let r = signature.verify(
            public_key_salt: message.response.publicKeySalt,
            public_key_hash: message.response.publicKeyHash,
            sign: message.signature, data: try message.response.serializedData()
        )
        if !r {
            throw ProtocolError.signatureVerifyFailed
        }
        return message.response
    }

    /// 解析Pong信息
    /// - parameters:
    /// - data: Response Data
    /// - returns: Handshake response
    public static func parsePong(crypto: Crypto, data: Data)
        throws -> Protocol_Pong
    {
        let plainData = try crypto.decrypt(data: data)
        let message = try Protocol_Pong(serializedBytes: plainData)
        return message
    }

    public static func buildPing(crypto: Crypto, id: PeerId) throws -> Data {
        var result = Data()
        result.append(5)

        var message = Protocol_Ping()
        message.id = id.id
        message.ts = Int32(Date().timeIntervalSince1970)
        let ping = try message.serializedData()
        let pingEncrypt = try crypto.encrypt(data: ping)
        result.append(pingEncrypt)

        return result
    }
    
    
    public static func buildClose(crypto: Crypto, id: PeerId) throws -> Data {
        var result = Data()
        result.append(0xFF)

        var message = Protocol_Close()
        message.id = id.id
        let close = try message.serializedData()
        let closeEncrypt = try crypto.encrypt(data: close)
        result.append(closeEncrypt)

        return result
    }

    public static func parseApplyIp(crypto: Crypto, data: Data)
        throws -> Protocol_ApplyIpResponse
    {
        let plainData = try crypto.decrypt(data: data)
        let message = try Protocol_ApplyIpResponse(serializedBytes: plainData)
        return message
    }

    public static func buildApplyIp(crypto: Crypto, id: PeerId, ip: String?)
        throws -> Data
    {
        var result = Data()
        result.append(3)

        var message = Protocol_ApplyIpRequest()
        message.id = id.id
        if let ip = ip {
            message.ip = ip
        }
        let ipApply = try message.serializedData()
        let ipApplyEncrypt = try crypto.encrypt(data: ipApply)
        result.append(ipApplyEncrypt)

        return result
    }

    public static func buildData(crypto: Crypto, data: Data) throws -> Data {
        var result = Data()
        result.append(9)
        let dataEncrypt = try crypto.encrypt(data: data)
        result.append(dataEncrypt)
        return result
    }

    public static func buildPeerQuery(crypto: Crypto, id: PeerId, ip: String)
        throws -> Data
    {
        var result = Data()
        result.append(0x20)

        var message = Protocol_PeerQueryRequest()
        message.id = id.id
        message.ip = ip
        let query = try message.serializedData()
        let queryEncrypt = try crypto.encrypt(data: query)
        result.append(queryEncrypt)

        return result
    }

    public static func parsePeerQuery(crypto: Crypto, data: Data)
        throws -> Protocol_PeerQueryResponse
    {
        let plainData = try crypto.decrypt(data: data)
        let message = try Protocol_PeerQueryResponse(serializedBytes: plainData)
        return message
    }
}
