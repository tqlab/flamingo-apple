//
//  Extension.swift
//  FlamingoCore
//
//  Created by Lee on 2024/11/20.
//
import CryptoKit

extension SharedSecret {
    var bytes: [UInt8] {
        withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            return Array(ptr)
        }
    }
}
