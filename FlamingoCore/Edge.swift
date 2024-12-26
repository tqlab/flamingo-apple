//
//  Peer.swift
//  FlamingoCore
//
//  Created by Lee on 2024/11/22.
//

import CryptoKit
import Foundation
import Network
import os.log

public enum EdgeError: Error {
    case connectionFailed
}

public class Edge {
    private let queue = DispatchQueue(
        label: "net.dighole.flamingo", attributes: .concurrent)
    private let log = OSLog(
        subsystem: "net.dighole.flamingo", category: "network")
    private let config: PeerConfig
    // 握手成功的回调方法，根据握手返回的ip设置到虚拟网卡中
    private var onHandshake: ((IPAddress) -> Void)
    // 收到网络数据包的回调方法，用于写回虚拟网卡
    private var onData: ((Data) -> Void)
    private var pendingCompletion: ((Error?) -> Void)

    private let signature: Signature
    private let peers: Peers
    private let id: Data
    // 每一个edge都有一个公私钥对，公钥将通过handshake包发送给远端，用于协商对称密钥，用于加解密
    private let privateKey: Curve25519.KeyAgreement.PrivateKey
    private var crypto: Crypto?
    // 重连定时任务
    private let reconnectTimer: DispatchSourceTimer
    // 心跳定时任务
    private let heartbeatTimer: DispatchSourceTimer
    private let algorithms: [Algorithm]
    private var lastActiveTime: Int

    init(
        config: PeerConfig, onHandshake: @escaping ((IPAddress) -> Void),
        onData: @escaping ((Data) -> Void),
        pendingCompletion: @escaping ((Error?) -> Void)
    )
        throws
    {
        self.config = config
        self.onHandshake = onHandshake
        self.onData = onData
        self.pendingCompletion = pendingCompletion
        self.signature = try Signature(password: config.password)
        self.peers = Peers()
        self.id = UUID().data
        self.privateKey = Crypto.createEcdhKeypair()

        self.reconnectTimer = DispatchSource.makeTimerSource(queue: .global())
        self.heartbeatTimer = DispatchSource.makeTimerSource(queue: .global())
        self.algorithms = try Edge.calculateAlgorithm()
        self.lastActiveTime = Int(Date().timeIntervalSince1970)
        
        let _ = self.peers.createPeer(host: config.host, port: config.port, superNode: true)

        reconnectTimer.schedule(
            deadline: .now() + 10.0, repeating: .seconds(10))
        reconnectTimer.setEventHandler {
            self.reconnect()
        }

    }

    ///
    /// 建立连接
    ///
    public func connect() {
        
        for peer in self.peers.getAll(){
            os_log(.info, log: self.log, "Start connect to \(peer.endpoint).")
            
            peer.connection.stateUpdateHandler = self.listenStateUpdate(to:)
            peer.connection.start(queue: self.queue)
        }

    }

    ///
    /// 断开链接
    ///
    public func disconnect() {
        self.reconnectTimer.cancel()
        self.heartbeatTimer.cancel()
        
        for peer in self.peers.getAll(){
            peer.connection.stateUpdateHandler = nil
            peer.connection.cancel()
        }
        
    }

    ///
    /// 向服务器写数据
    /// - parameters:
    /// - data:本地网卡读取的数据
    /// - throws
    /// - returns: Void
    ///
    public func writeData(_ data: Data) throws {
        guard let crypto = self.crypto else { return }
        let e = try crypto.encrypt(data: data)
        var d = Data()
        d.append(contentsOf: [9])
        d.append(contentsOf: e)
        self.sendData(data: d)
    }

    ///
    /// 重连
    ///
    private func reconnect() {
        for peer in self.peers.getAll(){
            // 如果链接失败超过5次，通知链接失败
            if peer.isSuperNode() && peer.faildTimes > 5 {
                self.pendingCompletion(EdgeError.connectionFailed)
            } else {
                let time = Int(Date().timeIntervalSince1970)
                if peer.connection.state != .ready || peer.faildTimes > 0
                    || time - self.lastActiveTime > 10
                {
                    os_log(.error, log: self.log, "Start to reconnect.")

                    peer.faildTimes += 1
                    peer.connection.restart()
                }
            }
        }
        
    }

    ///
    /// 发送心跳包
    ///
    private func heartbeat() {
        // send heartbeat
        do {
            let data = try Protocol.buildPing(crypto: self.crypto!)
            os_log(.info, log: self.log, "Send heartbeat packet.")
            self.sendData(data: data)
        } catch {
            os_log(
                .error, log: self.log, "Heartbeat error: %{public}@", "\(error)"
            )
        }
        //
    }

    ///
    /// 握手
    ///
    private func handshake() {
        do {
            let data = try Protocol.buildHandshakeRequest(
                signature: self.signature,
                id: self.id,
                publicKey: self.privateKey.publicKey.rawRepresentation,
                algorithms: self.algorithms)
            os_log(.info, log: self.log, "Send handshake packet")
            self.sendData(data: data)
        } catch {
            os_log(
                .error, log: self.log, "Handshake error: %{public}@", "\(error)"
            )
        }
    }

    ///
    /// 发送数据包
    ///
    private func sendData(data: Data) {
        self.connection.send(
            content: data,
            completion: .contentProcessed({ nWError in
                if let error = nWError {
                    os_log(
                        .error, log: self.log, "Send data error: %{public}@",
                        "\(error)")
                    return
                }
            }))
    }

    ///
    /// 接收数据
    ///
    private func receiveData() {
        self.connection.receive(minimumIncompleteLength: 1, maximumLength: 8192)
        { [weak self] (content, contentContext, isComplete, error) in

            guard let weakSelf = self else { return }
            if let nWError = error {
                os_log(
                    .error, log: weakSelf.log, "Receive data error: %{public}@",
                    "\(nWError)")
                weakSelf.faildTimes = weakSelf.faildTimes + 1
                Thread.sleep(forTimeInterval: 0.2)
            }
            // 更新收到数据的时间
            weakSelf.lastActiveTime = Int(Date().timeIntervalSince1970)

            let state = weakSelf.connection.state
            if state == .ready {
                if let data = content, !data.isEmpty {
                    weakSelf.handleData(data: data)
                }
            }
            weakSelf.receiveData()
        }
    }

    ///
    /// 数据处理
    ///
    private func handleData(data: Data) {
        let type = data.bytes[0]
        switch type {
        case 1:
            // Handshake response
            do {
                let response = try Protocol.parseHandshakeResponse(
                    signature: self.signature, data: data[1...])
                let publicKey = response.publicKeyData
                let algorithmType = AlgorithmType.fromCode(
                    code: response.algorithm.algorithmType.rawValue)
                guard let type = algorithmType else { return }
                // 握手成功，初始化加密套件，用于后续数据的加密操作
                self.crypto = try Crypto(
                    privateKey: self.privateKey, algorithmType: type,
                    publicKey: publicKey)
                os_log(
                    .info, log: self.log,
                    "Handshake successfully! \(type.toString())")

                // 初始化成功后，每隔10s发送一次心跳包。
                heartbeatTimer.schedule(
                    deadline: .now() + 10.0, repeating: .seconds(10))
                heartbeatTimer.setEventHandler {
                    self.heartbeat()
                }
            } catch {
                os_log(
                    .error, log: self.log,
                    "Parse handshake response error: \(error)")
            }
        case 2:
            // supernode拒绝，需要重新握手
            self.handshake()
        case 5:
            // 心跳包处理
            do {
                guard let crypto = self.crypto else { return }
                let pong = try Protocol.parsePong(crypto: crypto, data: data[1...])

                os_log(
                    .info, log: self.log, "Received pong. timestamp: \(pong.ts)"
                )

            } catch {
                os_log(.error, log: self.log, "Decrypt data error: \(error)")
            }
        case 9:
            do {
                guard let crypto = self.crypto else { return }
                let result = try crypto.decrypt(data: data[1...])
                self.onData(result)
            } catch {
                os_log(.error, log: self.log, "Decrypt data error: \(error)")
            }
        default:
            os_log(.error, log: self.log, "Unknown type: \(type)")
        }
    }

    private func listenStateUpdate(to state: NWConnection.State) {
        switch state {
        case .setup:
            print("The connection has been initialized but not started.")
        case .waiting(let nWError):
            self.faildTimes = self.faildTimes + 1
            os_log(
                .error, log: self.log,
                "The connection is waiting for a network path chage with: %{public}@",
                "\(nWError)")
        case .preparing:
            print("The connection int the process of being established.")
        case .ready:
            print(
                "The connection is established, and ready to send and receive data."
            )
            self.faildTimes = 0
            self.handshake()
            self.receiveData()
            self.reconnectTimer.resume()
            self.heartbeatTimer.resume()
        case .failed(let nWError):
            self.faildTimes = self.faildTimes + 1
            os_log(
                .error, log: self.log,
                "The connection has disconnected or encountered an: %{public}@",
                "\(nWError)")
        case .cancelled:
            print("The connection has been cancelled.")
        @unknown default:
            self.faildTimes = self.faildTimes + 1
            os_log(.error, log: self.log, "Unknown error")

        }
    }

    private static func calculateAlgorithm() throws -> [Algorithm] {
        var algorithms: [Algorithm] = Array()

        let speed = try Crypto.testSpeed(
            algorithmType: AlgorithmType.AES_GCM_128, maxNanoTime: 100_000_000)
        let speed2 = try Crypto.testSpeed(
            algorithmType: AlgorithmType.AES_GCM_256, maxNanoTime: 100_000_000)
        let speed3 = try Crypto.testSpeed(
            algorithmType: AlgorithmType.CHACHA20_POLY1305,
            maxNanoTime: 100_000_000)
        let a1 = Algorithm(type: AlgorithmType.AES_GCM_128, speed: speed)
        let a2 = Algorithm(type: AlgorithmType.AES_GCM_256, speed: speed2)
        let a3 = Algorithm(type: AlgorithmType.CHACHA20_POLY1305, speed: speed3)

        algorithms.append(a1)
        algorithms.append(a2)
        algorithms.append(a3)

        return algorithms
    }
}
