//
//  Data+Additions.swift
//
//
//  Created by Bryan Montz on 6/20/23.
//

import Crypto
import Foundation

extension Data {
    
    /// The SHA256 hash of the data.
    var sha256: Data {
        let sha256 = SHA256.hash(data: self)
        return Data(sha256)
    }
    
    /// Random data of a given size.
    static func randomBytes(count: Int) -> Data {
        var bytes = [Int8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("can't copy secure random data")
        }
        return Data(bytes: bytes, count: count)
    }
}
