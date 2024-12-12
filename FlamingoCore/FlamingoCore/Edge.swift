//
//  Edge.swift
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
    private let config: EdgeConfig
    private var pendingCompletion: ((Error?) -> Void)
    private let signature: Signature
    private let connection: NWConnection
    // 每一个edge都有一个公私钥对，公钥将通过handshake包发送给远端，用于协商对称密钥，用于加解密
    private let privateKey: Curve25519.KeyAgreement.PrivateKey
    private var crypto: Crypto?
    private var faildTimes = 0
    // 重连定时任务
    private let reconnectTimer: DispatchSourceTimer
    // 心跳定时任务
    private let heartbeatTimer: DispatchSourceTimer
    private let algorithms: [Algorithm]

    init(config: EdgeConfig, pendingCompletion: @escaping ((Error?) -> Void))
        throws
    {
        self.config = config
        self.pendingCompletion = pendingCompletion
        self.signature = try Signature(password: config.password)
        let endpoint = Network.NWEndpoint.hostPort(
            host: NWEndpoint.Host(config.host),
            port: NWEndpoint.Port(integerLiteral: config.port))
        self.connection = NWConnection(to: endpoint, using: .udp)
        self.privateKey = Crypto.createEcdhKeypair()

        self.reconnectTimer = DispatchSource.makeTimerSource(queue: .global())
        self.heartbeatTimer = DispatchSource.makeTimerSource(queue: .global())
        self.algorithms = try Edge.calculateAlgorithm()

        reconnectTimer.schedule(
            deadline: .now() + 10.0, repeating: .seconds(10))
        reconnectTimer.setEventHandler {
            self.reconnect()
        }
        heartbeatTimer.schedule(
            deadline: .now() + 10.0, repeating: .seconds(10))
        heartbeatTimer.setEventHandler {
            self.heartbeat()
        }
    }

    ///
    /// 建立连接
    ///
    public func connect() {
        self.connection.stateUpdateHandler = self.listenStateUpdate(to:)
        self.connection.start(queue: self.queue)
    }

    ///
    /// 断开链接
    ///
    public func disconnect() {
        self.reconnectTimer.cancel()
        self.heartbeatTimer.cancel()
        self.connection.stateUpdateHandler = nil
        self.connection.cancel()
    }

    ///
    /// 重连
    ///
    private func reconnect() {
        // 如果链接失败超过5次，通知链接失败
        if self.faildTimes > 5 {
            self.pendingCompletion(EdgeError.connectionFailed)
        } else {
            if self.connection.state != .ready || self.faildTimes > 0 {
                self.disconnect()
                self.connect()
            }
        }
    }

    ///
    /// 发送心跳包
    ///
    private func heartbeat() {
        // send heartbeat
        do {
            let data = try Protocol.buildHeartbeatRequest()
            os_log(.error, log: self.log, "Send heartbeat packet.")
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
                publicKey: self.privateKey.publicKey.rawRepresentation,
                ip: "192.168.10.2",
                mac: Data(), algorithms: self.algorithms)
            os_log(.error, log: self.log, "Send handshake packet.")
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
                print("Send data successfully: \(data.count)")
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
            }

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
                print("response: \(response)")
            } catch {
                os_log(
                    .error, log: self.log,
                    "Parse handshake response error: \(error)")
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
        var a1 = Algorithm(type: AlgorithmType.AES_GCM_128, speed: speed)
        var a2 = Algorithm(type: AlgorithmType.AES_GCM_256, speed: speed2)
        var a3 = Algorithm(type: AlgorithmType.CHACHA20_POLY1305, speed: speed3)

        algorithms.append(a1)
        algorithms.append(a2)
        algorithms.append(a3)

        return algorithms
    }
}
