//
//  DirectMessageEncrypting.swift
//
//
//  Created by Joel Klabo on 8/10/23.
//

import Foundation
import secp256k1
import Crypto

public enum DirectMessageEncryptingError: Error {
    case pubkeyInvalid
    case unsuccessfulExponentiation
    case encryptionError
    case decryptionError
    case missingValue
}

public protocol DirectMessageEncrypting {}
public extension DirectMessageEncrypting {

    func encrypt(content: String, privateKey: PrivateKey, publicKey: PublicKey) throws -> String {

        let sharedSecret = try getSharedSecret(privateKey: privateKey, recipient: publicKey)
        
        let iv = [UInt8].random(count: 16)
        let utf8Content = Array(content.utf8)
        guard let encryptedMessage = try? AES.GCM.seal(utf8Content, using: SymmetricKey(data: sharedSecret), nonce: AES.GCM.Nonce(data: iv)).combined else {
            throw DirectMessageEncryptingError.encryptionError
        }

        return encodeDMBase64(content: encryptedMessage.bytes, iv: iv)
    }

    func decrypt(encryptedContent message: String, privateKey: PrivateKey, publicKey: PublicKey) throws -> String {
        guard let sharedSecret = try? getSharedSecret(privateKey: privateKey, recipient: publicKey) else {
            throw EventCreatingError.invalidInput
        }

        let sections = Array(message.split(separator: "?"))

        if sections.count != 2 {
            throw DirectMessageEncryptingError.decryptionError
        }

        guard let encryptedContent = sections.first,
              let encryptedContentData = Data(base64Encoded: String(encryptedContent)) else {
            throw DirectMessageEncryptingError.decryptionError
        }

        guard let ivContent = sections.last else {
            throw DirectMessageEncryptingError.decryptionError
        }

        let ivContentTrimmed = ivContent.dropFirst(3)

        guard let ivContentData = Data(base64Encoded: String(ivContentTrimmed)),
              let sealedBox = try? AES.GCM.SealedBox(combined: encryptedContentData),
              let decryptedContentData = try? AES.GCM.open(sealedBox, using: SymmetricKey(data: sharedSecret)),
              let decryptedMessage = String(data: Data(decryptedContentData), encoding: .utf8) else {
            throw DirectMessageEncryptingError.decryptionError
        }

        return decryptedMessage
    }

    private func getSharedSecret(privateKey: PrivateKey, recipient pubkey: PublicKey) throws -> [UInt8] {
        let privateKeyBytes = privateKey.dataRepresentation.bytes
        let publicKeyBytes = preparePublicKeyBytes(from: pubkey)

        let recipientPublicKey = try parsePublicKey(from: publicKeyBytes)
        return try computeSharedSecret(using: recipientPublicKey, and: privateKeyBytes)
    }

    private func preparePublicKeyBytes(from pubkey: PublicKey) -> [UInt8] {
        var bytes = pubkey.dataRepresentation.bytes
        bytes.insert(2, at: 0)
        return bytes
    }

    private func parsePublicKey(from bytes: [UInt8]) throws -> secp256k1_pubkey {
        var recipientPublicKey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_parse(secp256k1.Context.rawRepresentation, &recipientPublicKey, bytes, bytes.count) != 0 else {
            throw DirectMessageEncryptingError.pubkeyInvalid
        }
        return recipientPublicKey
    }

    private func computeSharedSecret(using publicKey: secp256k1_pubkey, and privateKeyBytes: [UInt8]) throws -> [UInt8] {
        var sharedSecret = [UInt8](repeating: 0, count: 32)
        var mutablePublicKey = publicKey
        guard secp256k1_ecdh(secp256k1.Context.rawRepresentation, &sharedSecret, &mutablePublicKey, privateKeyBytes, { (output, x32, _, _) in
            memcpy(output, x32, 32)
            return 1
        }, nil) != 0 else {
            throw DirectMessageEncryptingError.unsuccessfulExponentiation
        }
        return sharedSecret
    }

    private func encodeDMBase64(content: [UInt8], iv: [UInt8]) -> String {
        let contentBase64 = Data(content).base64EncodedString()
        let ivBase64 = Data(iv).base64EncodedString()
        return contentBase64 + "?iv=" + ivBase64
    }
}

// Warning: Probably not cryptographically safe.
extension Array where Element == UInt8 {
    static func random(count: Int) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: count)
        for i in 0..<count {
            result[i] = UInt8.random(in: 0...UInt8.max)
        }
        return result
    }
}

