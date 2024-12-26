//
//  Extension.swift
//  FlamingoCore
//
//  Created by Lee on 2024/11/20.
//
import CryptoKit
import Foundation

extension SharedSecret {
    var bytes: [UInt8] {
        withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            return Array(ptr)
        }
    }
}

extension Data {

    public var bytes: [UInt8] {
        return [UInt8](self)
    }
    
    /// Returns cryptographically secure random data.
    ///
    /// - Parameter length: Length of the data in bytes.
    /// - Returns: Generated data of the specified length.
    static func random(length: Int) -> Data {
        var randomNumberGenerator = SystemRandomNumberGenerator()
        return Data(
            (0..<length).map { _ in
                UInt8.random(
                    in: UInt8.min...UInt8.max, using: &randomNumberGenerator)
            })
    }
}

extension Digest {
    public var bytes: [UInt8] { Array(makeIterator()) }
}

extension UUID {

    public var data: Data {
        return withUnsafeBytes(of: self.uuid, { Data($0) })
    }

}

extension SymmetricKey {

    var data: Data {
        withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            return Data(Array(ptr))
        }
    }
}
