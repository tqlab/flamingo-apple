// DO NOT EDIT.
// swift-format-ignore-file
// swiftlint:disable all
//
// Generated by the Swift generator plugin for the protocol buffer compiler.
// Source: Protocol.proto
//
// For information on using the generated types, please see the documentation:
//   https://github.com/apple/swift-protobuf/

import Foundation
import SwiftProtobuf

// If the compiler emits an error on this type, it is because this file
// was generated by a version of the `protoc` Swift plug-in that is
// incompatible with the version of SwiftProtobuf to which you are linking.
// Please ensure that you are building against the same version of the API
// that was used to generate this file.
fileprivate struct _GeneratedWithProtocGenSwiftVersion: SwiftProtobuf.ProtobufAPIVersionCheck {
  struct _2: SwiftProtobuf.ProtobufAPIVersion_2 {}
  typealias Version = _2
}

enum Protocol_AlgorithmType: SwiftProtobuf.Enum, Swift.CaseIterable {
  typealias RawValue = Int
  case aes128Gcm // = 0
  case aes256Gcm // = 1
  case chacha20Poly1305 // = 2
  case UNRECOGNIZED(Int)

  init() {
    self = .aes128Gcm
  }

  init?(rawValue: Int) {
    switch rawValue {
    case 0: self = .aes128Gcm
    case 1: self = .aes256Gcm
    case 2: self = .chacha20Poly1305
    default: self = .UNRECOGNIZED(rawValue)
    }
  }

  var rawValue: Int {
    switch self {
    case .aes128Gcm: return 0
    case .aes256Gcm: return 1
    case .chacha20Poly1305: return 2
    case .UNRECOGNIZED(let i): return i
    }
  }

  // The compiler won't synthesize support with the UNRECOGNIZED case.
  static let allCases: [Protocol_AlgorithmType] = [
    .aes128Gcm,
    .aes256Gcm,
    .chacha20Poly1305,
  ]

}

struct Protocol_Algorithm: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var algorithmType: Protocol_AlgorithmType = .aes128Gcm

  var speed: Float = 0

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

struct Protocol_HandshakeRequest: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var id: Data = Data()

  var publicKeySalt: Data = Data()

  var publicKeyHash: Data = Data()

  var publicKeyData: Data = Data()

  var algorithms: [Protocol_Algorithm] = []

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

struct Protocol_HandshakeResponse: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var id: Data = Data()

  var publicKeySalt: Data = Data()

  var publicKeyHash: Data = Data()

  var publicKeyData: Data = Data()

  var algorithm: Protocol_Algorithm {
    get {return _algorithm ?? Protocol_Algorithm()}
    set {_algorithm = newValue}
  }
  /// Returns true if `algorithm` has been explicitly set.
  var hasAlgorithm: Bool {return self._algorithm != nil}
  /// Clears the value of `algorithm`. Subsequent reads from it will return its default value.
  mutating func clearAlgorithm() {self._algorithm = nil}

  var cidr: String = String()

  var payload: Data = Data()

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}

  fileprivate var _algorithm: Protocol_Algorithm? = nil
}

struct Protocol_HandshakeMessage: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var signature: Data = Data()

  var data: Protocol_HandshakeMessage.OneOf_Data? = nil

  var request: Protocol_HandshakeRequest {
    get {
      if case .request(let v)? = data {return v}
      return Protocol_HandshakeRequest()
    }
    set {data = .request(newValue)}
  }

  var response: Protocol_HandshakeResponse {
    get {
      if case .response(let v)? = data {return v}
      return Protocol_HandshakeResponse()
    }
    set {data = .response(newValue)}
  }

  var unknownFields = SwiftProtobuf.UnknownStorage()

  enum OneOf_Data: Equatable, Sendable {
    case request(Protocol_HandshakeRequest)
    case response(Protocol_HandshakeResponse)

  }

  init() {}
}

struct Protocol_IpApplyRequest: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var id: Data = Data()

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

struct Protocol_IpApplyResponse: @unchecked Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var id: Data = Data()

  var ip: String = String()

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

struct Protocol_Ping: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var ts: Int32 = 0

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

struct Protocol_Pong: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var ts: Int32 = 0

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

struct Protocol_PeerQueryRequest: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var ip: String = String()

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

struct Protocol_PeerQueryResponse: Sendable {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var ip: String = String()

  var addr: String = String()

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

// MARK: - Code below here is support for the SwiftProtobuf runtime.

fileprivate let _protobuf_package = "protocol"

extension Protocol_AlgorithmType: SwiftProtobuf._ProtoNameProviding {
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    0: .same(proto: "AES_128_GCM"),
    1: .same(proto: "AES_256_GCM"),
    2: .same(proto: "CHACHA20_POLY1305"),
  ]
}

extension Protocol_Algorithm: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".Algorithm"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "algorithm_type"),
    2: .same(proto: "speed"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularEnumField(value: &self.algorithmType) }()
      case 2: try { try decoder.decodeSingularFloatField(value: &self.speed) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if self.algorithmType != .aes128Gcm {
      try visitor.visitSingularEnumField(value: self.algorithmType, fieldNumber: 1)
    }
    if self.speed.bitPattern != 0 {
      try visitor.visitSingularFloatField(value: self.speed, fieldNumber: 2)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Protocol_Algorithm, rhs: Protocol_Algorithm) -> Bool {
    if lhs.algorithmType != rhs.algorithmType {return false}
    if lhs.speed != rhs.speed {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Protocol_HandshakeRequest: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".HandshakeRequest"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "id"),
    2: .standard(proto: "public_key_salt"),
    3: .standard(proto: "public_key_hash"),
    4: .standard(proto: "public_key_data"),
    5: .same(proto: "algorithms"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBytesField(value: &self.id) }()
      case 2: try { try decoder.decodeSingularBytesField(value: &self.publicKeySalt) }()
      case 3: try { try decoder.decodeSingularBytesField(value: &self.publicKeyHash) }()
      case 4: try { try decoder.decodeSingularBytesField(value: &self.publicKeyData) }()
      case 5: try { try decoder.decodeRepeatedMessageField(value: &self.algorithms) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.id.isEmpty {
      try visitor.visitSingularBytesField(value: self.id, fieldNumber: 1)
    }
    if !self.publicKeySalt.isEmpty {
      try visitor.visitSingularBytesField(value: self.publicKeySalt, fieldNumber: 2)
    }
    if !self.publicKeyHash.isEmpty {
      try visitor.visitSingularBytesField(value: self.publicKeyHash, fieldNumber: 3)
    }
    if !self.publicKeyData.isEmpty {
      try visitor.visitSingularBytesField(value: self.publicKeyData, fieldNumber: 4)
    }
    if !self.algorithms.isEmpty {
      try visitor.visitRepeatedMessageField(value: self.algorithms, fieldNumber: 5)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Protocol_HandshakeRequest, rhs: Protocol_HandshakeRequest) -> Bool {
    if lhs.id != rhs.id {return false}
    if lhs.publicKeySalt != rhs.publicKeySalt {return false}
    if lhs.publicKeyHash != rhs.publicKeyHash {return false}
    if lhs.publicKeyData != rhs.publicKeyData {return false}
    if lhs.algorithms != rhs.algorithms {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Protocol_HandshakeResponse: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".HandshakeResponse"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "id"),
    2: .standard(proto: "public_key_salt"),
    3: .standard(proto: "public_key_hash"),
    4: .standard(proto: "public_key_data"),
    5: .same(proto: "algorithm"),
    6: .same(proto: "cidr"),
    7: .same(proto: "payload"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBytesField(value: &self.id) }()
      case 2: try { try decoder.decodeSingularBytesField(value: &self.publicKeySalt) }()
      case 3: try { try decoder.decodeSingularBytesField(value: &self.publicKeyHash) }()
      case 4: try { try decoder.decodeSingularBytesField(value: &self.publicKeyData) }()
      case 5: try { try decoder.decodeSingularMessageField(value: &self._algorithm) }()
      case 6: try { try decoder.decodeSingularStringField(value: &self.cidr) }()
      case 7: try { try decoder.decodeSingularBytesField(value: &self.payload) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    if !self.id.isEmpty {
      try visitor.visitSingularBytesField(value: self.id, fieldNumber: 1)
    }
    if !self.publicKeySalt.isEmpty {
      try visitor.visitSingularBytesField(value: self.publicKeySalt, fieldNumber: 2)
    }
    if !self.publicKeyHash.isEmpty {
      try visitor.visitSingularBytesField(value: self.publicKeyHash, fieldNumber: 3)
    }
    if !self.publicKeyData.isEmpty {
      try visitor.visitSingularBytesField(value: self.publicKeyData, fieldNumber: 4)
    }
    try { if let v = self._algorithm {
      try visitor.visitSingularMessageField(value: v, fieldNumber: 5)
    } }()
    if !self.cidr.isEmpty {
      try visitor.visitSingularStringField(value: self.cidr, fieldNumber: 6)
    }
    if !self.payload.isEmpty {
      try visitor.visitSingularBytesField(value: self.payload, fieldNumber: 7)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Protocol_HandshakeResponse, rhs: Protocol_HandshakeResponse) -> Bool {
    if lhs.id != rhs.id {return false}
    if lhs.publicKeySalt != rhs.publicKeySalt {return false}
    if lhs.publicKeyHash != rhs.publicKeyHash {return false}
    if lhs.publicKeyData != rhs.publicKeyData {return false}
    if lhs._algorithm != rhs._algorithm {return false}
    if lhs.cidr != rhs.cidr {return false}
    if lhs.payload != rhs.payload {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Protocol_HandshakeMessage: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".HandshakeMessage"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "signature"),
    2: .same(proto: "request"),
    3: .same(proto: "response"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBytesField(value: &self.signature) }()
      case 2: try {
        var v: Protocol_HandshakeRequest?
        var hadOneofValue = false
        if let current = self.data {
          hadOneofValue = true
          if case .request(let m) = current {v = m}
        }
        try decoder.decodeSingularMessageField(value: &v)
        if let v = v {
          if hadOneofValue {try decoder.handleConflictingOneOf()}
          self.data = .request(v)
        }
      }()
      case 3: try {
        var v: Protocol_HandshakeResponse?
        var hadOneofValue = false
        if let current = self.data {
          hadOneofValue = true
          if case .response(let m) = current {v = m}
        }
        try decoder.decodeSingularMessageField(value: &v)
        if let v = v {
          if hadOneofValue {try decoder.handleConflictingOneOf()}
          self.data = .response(v)
        }
      }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    if !self.signature.isEmpty {
      try visitor.visitSingularBytesField(value: self.signature, fieldNumber: 1)
    }
    switch self.data {
    case .request?: try {
      guard case .request(let v)? = self.data else { preconditionFailure() }
      try visitor.visitSingularMessageField(value: v, fieldNumber: 2)
    }()
    case .response?: try {
      guard case .response(let v)? = self.data else { preconditionFailure() }
      try visitor.visitSingularMessageField(value: v, fieldNumber: 3)
    }()
    case nil: break
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Protocol_HandshakeMessage, rhs: Protocol_HandshakeMessage) -> Bool {
    if lhs.signature != rhs.signature {return false}
    if lhs.data != rhs.data {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Protocol_IpApplyRequest: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".IpApplyRequest"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "id"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBytesField(value: &self.id) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.id.isEmpty {
      try visitor.visitSingularBytesField(value: self.id, fieldNumber: 1)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Protocol_IpApplyRequest, rhs: Protocol_IpApplyRequest) -> Bool {
    if lhs.id != rhs.id {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Protocol_IpApplyResponse: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".IpApplyResponse"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "id"),
    2: .same(proto: "ip"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBytesField(value: &self.id) }()
      case 2: try { try decoder.decodeSingularStringField(value: &self.ip) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.id.isEmpty {
      try visitor.visitSingularBytesField(value: self.id, fieldNumber: 1)
    }
    if !self.ip.isEmpty {
      try visitor.visitSingularStringField(value: self.ip, fieldNumber: 2)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Protocol_IpApplyResponse, rhs: Protocol_IpApplyResponse) -> Bool {
    if lhs.id != rhs.id {return false}
    if lhs.ip != rhs.ip {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Protocol_Ping: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".Ping"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "ts"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularInt32Field(value: &self.ts) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if self.ts != 0 {
      try visitor.visitSingularInt32Field(value: self.ts, fieldNumber: 1)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Protocol_Ping, rhs: Protocol_Ping) -> Bool {
    if lhs.ts != rhs.ts {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Protocol_Pong: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".Pong"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "ts"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularInt32Field(value: &self.ts) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if self.ts != 0 {
      try visitor.visitSingularInt32Field(value: self.ts, fieldNumber: 1)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Protocol_Pong, rhs: Protocol_Pong) -> Bool {
    if lhs.ts != rhs.ts {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Protocol_PeerQueryRequest: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".PeerQueryRequest"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "ip"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularStringField(value: &self.ip) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.ip.isEmpty {
      try visitor.visitSingularStringField(value: self.ip, fieldNumber: 1)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Protocol_PeerQueryRequest, rhs: Protocol_PeerQueryRequest) -> Bool {
    if lhs.ip != rhs.ip {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Protocol_PeerQueryResponse: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".PeerQueryResponse"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "ip"),
    2: .same(proto: "addr"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularStringField(value: &self.ip) }()
      case 2: try { try decoder.decodeSingularStringField(value: &self.addr) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.ip.isEmpty {
      try visitor.visitSingularStringField(value: self.ip, fieldNumber: 1)
    }
    if !self.addr.isEmpty {
      try visitor.visitSingularStringField(value: self.addr, fieldNumber: 2)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Protocol_PeerQueryResponse, rhs: Protocol_PeerQueryResponse) -> Bool {
    if lhs.ip != rhs.ip {return false}
    if lhs.addr != rhs.addr {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}