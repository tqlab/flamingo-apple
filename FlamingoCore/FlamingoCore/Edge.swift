import CryptoKit
//
//  Edge.swift
//  FlamingoCore
//
//  Created by Lee on 2024/12/25.
//
import Foundation
internal import NIOCore
internal import NIOPosix
import Network
import os.log

public enum EdgeError: Error {
    case connectionFailed
}

public class Edge {
    private static let log = OSLog(
        subsystem: "net.dighole.flamingo", category: "network")
    private static let queue = DispatchQueue(
        label: "net.dighole.flamingo", attributes: .concurrent)
    // 每一个edge都有一个公私钥对，公钥将通过handshake包发送给远端，用于协商对称密钥，用于加解密
    private static let privateKey: Curve25519.KeyAgreement.PrivateKey =
        Crypto.createEcdhKeypair()
    private static let id: Data = UUID().data
    private static let algorithms: [Algorithm] = calculateAlgorithm()
    private let group = MultiThreadedEventLoopGroup(
        numberOfThreads: System.coreCount)
    private let bootstrap: DatagramBootstrap

    private let peers: Peers
    // 心跳定时任务
    private let heartbeatTimer: DispatchSourceTimer

    init(
        config: PeerConfig,
        onIp: @escaping ((IPAddress) -> Void),
        onData: @escaping ((Data) -> Void),
        pendingCompletion: @escaping ((Error?) -> Void)
    )
        throws
    {
        var superNodeIp: String
        if Dns.isIpAddress(str: config.host) {
            superNodeIp = config.host
        } else {
            let ipList = try Dns.parse(domain: config.host)
            if ipList.count < 1 {
                throw EdgeError.connectionFailed
            }
            superNodeIp = ipList[0]
        }
        self.peers = Peers(superNodeIp: superNodeIp)
        self.heartbeatTimer = DispatchSource.makeTimerSource(queue: Edge.queue)

        let signature = try Signature(password: config.password)
        let handler = UDPClientHandler(
            peers: self.peers,
            signature: signature,
            superNodeIp: superNodeIp, onIp: onIp, onData: onData)

        self.bootstrap = DatagramBootstrap(group: group)
            // Enable SO_REUSEADDR.
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.pipeline.addHandler(handler)
            }

        heartbeatTimer.schedule(
            deadline: .now() + 10.0, repeating: .seconds(10))
        heartbeatTimer.setEventHandler {
            self.heartbeat()
        }
        heartbeatTimer.activate()

        //
        let address = try SocketAddress.init(
            ipAddress: superNodeIp, port: Int(config.port))
        let _ = try bootstrap.connect(
            to: address
        ).wait()

    }

    public func writeData(data: Data) throws {
        if let ipPacket = SimpleIpPacket(data: data) {
            if let peer = self.peers.findPeer(ip: ipPacket.destation) {

                let data = try Protocol.buildData(
                    crypto: peer.crypto, data: data)
                let _ = peer.channel.writeAndFlush(
                    ByteBuffer(bytes: data.bytes))
            }
        }
    }

    ///
    /// 发送心跳包
    ///
    private func heartbeat() {
        // send heartbeat
        do {

            for peer in self.peers.getAll() {
                let data = try Protocol.buildPing(crypto: peer.crypto)
                let _ = peer.channel.writeAndFlush(
                    ByteBuffer(bytes: data.bytes))
            }
            os_log(.info, log: Edge.log, "Send heartbeat packet.")

        } catch {
            os_log(
                .error, log: Edge.log, "Heartbeat error: %{public}@", "\(error)"
            )
        }
        //
    }

    final class UDPClientHandler: ChannelInboundHandler {
        public typealias InboundIn = AddressedEnvelope<ByteBuffer>
        public typealias OutboundOut = ByteBuffer

        private var receiveBuffer: ByteBuffer = ByteBuffer()
        private var peers: Peers
        private var signature: Signature
        private var superNodeIp: String
        // 握手成功的回调方法，根据握手返回的ip设置到虚拟网卡中
        private var onIp: ((IPAddress) -> Void)
        // 收到网络数据包的回调方法，用于写回虚拟网卡
        private var onData: ((Data) -> Void)

        init(
            peers: Peers,
            signature: Signature,
            superNodeIp: String,
            onIp: @escaping ((IPAddress) -> Void),
            onData: @escaping ((Data) -> Void)
        ) {
            self.peers = peers
            self.signature = signature
            self.superNodeIp = superNodeIp
            self.onIp = onIp
            self.onData = onData
        }

        ///
        /// 握手
        ///
        private func handshake(channel: Channel) {
            do {
                let data = try Protocol.buildHandshakeRequest(
                    signature: self.signature,
                    id: id,
                    publicKey: privateKey.publicKey.rawRepresentation,
                    algorithms: algorithms)
                os_log(.info, log: log, "Send handshake packet")

                let _ = channel.writeAndFlush(ByteBuffer(bytes: data.bytes))
            } catch {
                os_log(
                    .error, log: log, "Handshake error: %{public}@",
                    "\(error)"
                )
            }
        }

        public func channelActive(context: ChannelHandlerContext) {
            context.fireChannelActive()
            self.handshake(channel: context.channel)
        }

        public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            context.fireChannelActive()
            var unwrappedInboundData = self.unwrapInboundIn(data)
            receiveBuffer.clear()
            receiveBuffer.writeBuffer(&unwrappedInboundData.data)

            guard
                let bytes = receiveBuffer.readBytes(
                    length: receiveBuffer.readableBytes)
            else {
                return
            }

            let type = bytes[0]
            switch type {
            case 1:
                do {

                    let response = try Protocol.parseHandshakeResponse(
                        signature: self.signature, data: Data(bytes[1...]))
                    let publicKey = response.publicKeyData
                    let algorithmType = AlgorithmType.fromCode(
                        code: response.algorithm.algorithmType.rawValue)
                    guard let type = algorithmType else { return }
                    // 握手成功，初始化加密套件，用于后续数据的加密操作
                    let crypto = try Crypto(
                        privateKey: privateKey, algorithmType: type,
                        publicKey: publicKey)

                    let ip = context.remoteAddress!
                        .ipAddress!
                    let superNode =
                        self.superNodeIp == ip
                    let peer = self.peers.createPeer(
                        ip: ip,
                        id: PeerId(id: response.id),
                        channel: context.channel, crypto: crypto,
                        superNode: superNode)
                    os_log(
                        .info, log: log,
                        "Handshake successfully! \(type.toString())")

                    if superNode {
                        // apply ip
                        let data = try Protocol.buildApplyIp(
                            crypto: peer.crypto, id: Edge.id)
                        let _ = peer.channel.writeAndFlush(
                            ByteBuffer(bytes: data.bytes))
                    }
                } catch {
                    os_log(
                        .error, log: log,
                        "Parse handshake response error: \(error)")
                }
            case 2:
                // supernode拒绝，需要重新握手
                handshake(channel: context.channel)
            case 3:
                do {
                    let ip = context.remoteAddress!
                        .ipAddress!
                    guard let peer = self.peers.findPeerWithoutDefault(ip: ip)
                    else { return }

                    let applyIp = try Protocol.parseApplyIp(
                        crypto: peer.crypto, data: Data(bytes[1...]))
                    if let iPAddress = IPv4Address(applyIp.ip) {
                        self.onIp(iPAddress)
                    }

                    os_log(
                        .info, log: log,
                        "Received new ip address! \(applyIp.ip)")
                } catch {
                    os_log(
                        .error, log: log, "Decrypt data error: \(error)")
                }
            case 5:
                // 心跳包处理
                do {
                    let ip = context.remoteAddress!
                        .ipAddress!
                    guard let peer = self.peers.findPeerWithoutDefault(ip: ip)
                    else { return }
                    peer.updateActiveTime()

                    let pong = try Protocol.parsePong(
                        crypto: peer.crypto, data: Data(bytes[1...]))

                    os_log(
                        .info, log: log,
                        "Received pong. timestamp: \(pong.ts)"
                    )

                } catch {
                    os_log(
                        .error, log: log, "Decrypt data error: \(error)")
                }
            case 9:
                // 处理数据包
                do {
                    let ip = context.remoteAddress!
                        .ipAddress!
                    guard let peer = self.peers.findPeerWithoutDefault(ip: ip)
                    else { return }

                    let plainData = try peer.crypto.decrypt(
                        data: Data(bytes[1...]))
                    self.onData(plainData)
                } catch {
                    os_log(
                        .error, log: log, "Decrypt data error: \(error)")
                }
            default:
                os_log(.error, log: log, "Unknown type: \(type)")
            }
        }

        func channelInactive(context: ChannelHandlerContext) {
            // 如果是与supernode节点断开，则开启重连
            // context.remoteAddress
        }
    }

    private static func calculateAlgorithm() -> [Algorithm] {
        var algorithms: [Algorithm] = Array()

        do {
            let speed = try Crypto.testSpeed(
                algorithmType: AlgorithmType.AES_GCM_128,
                maxNanoTime: 100_000_000)
            let speed2 = try Crypto.testSpeed(
                algorithmType: AlgorithmType.AES_GCM_256,
                maxNanoTime: 100_000_000)
            let speed3 = try Crypto.testSpeed(
                algorithmType: AlgorithmType.CHACHA20_POLY1305,
                maxNanoTime: 100_000_000)
            let a1 = Algorithm(type: AlgorithmType.AES_GCM_128, speed: speed)
            let a2 = Algorithm(type: AlgorithmType.AES_GCM_256, speed: speed2)
            let a3 = Algorithm(
                type: AlgorithmType.CHACHA20_POLY1305, speed: speed3)

            os_log(
                .info, log: log,
                "AES_GCM_128: \(String(format: "%.1f MiB/s", speed)), AES_GCM_256: \(String(format: "%.1f MiB/s", speed2)), CHACHA20_POLY1305: \(String(format: "%.1f MiB/s", speed3))"
            )

            algorithms.append(a1)
            algorithms.append(a2)
            algorithms.append(a3)
        } catch {
            os_log(.error, log: log, "Crypto test speed error: \(error)")
        }

        return algorithms
    }
}
