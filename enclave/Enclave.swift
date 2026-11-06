#if os(macOS)
import CoreGraphics
#endif
import CryptoKit
import Foundation
import LocalAuthentication
import Security

// C ABI over CryptoKit, which is the only route to Secure Enclave ML-KEM and ML-DSA.
// Status codes match `device::enclave::Status`.

private let ok: Int32 = 0
private let unavailable: Int32 = 1
private let cancelled: Int32 = 2
private let failed: Int32 = 3
private let timedOut: Int32 = 4

private typealias Bytes = UnsafeBufferPointer<UInt8>

private func gated() -> SecAccessControl? {
    SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .userPresence],
        nil
    )
}

private func data(_ pointer: UnsafePointer<UInt8>, _ length: Int) -> Data {
    Data(bytes: pointer, count: length)
}

@_cdecl("lv_enclave_available")
public func lvEnclaveAvailable() -> Bool {
    SecureEnclave.isAvailable
}

/// Writes eight length-prefixed fields: a blob and a public key for each of the
/// key agreement, ML-KEM, signing and ML-DSA keys. Generating needs no touch.
@_cdecl("lv_enclave_generate")
public func lvEnclaveGenerate(
    _ out: UnsafeMutablePointer<UInt8>,
    _ capacity: Int,
    _ written: UnsafeMutablePointer<Int>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return unavailable }
    guard let control = gated() else { return failed }
    do {
        let agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: control)
        let kem = try SecureEnclave.MLKEM1024.PrivateKey(accessControl: control)
        let signing = try SecureEnclave.P256.Signing.PrivateKey(accessControl: control)
        let dsa = try SecureEnclave.MLDSA87.PrivateKey(accessControl: control)
        let fields: [Data] = [
            agreement.dataRepresentation, agreement.publicKey.x963Representation,
            kem.dataRepresentation, kem.publicKey.rawRepresentation,
            signing.dataRepresentation, signing.publicKey.x963Representation,
            dsa.dataRepresentation, dsa.publicKey.rawRepresentation,
        ]
        var offset = 0
        for field in fields {
            guard offset + 4 + field.count <= capacity else { return failed }
            let length = UInt32(field.count).littleEndian
            withUnsafeBytes(of: length) { (out + offset).update(from: $0.bindMemory(to: UInt8.self).baseAddress!, count: 4) }
            field.copyBytes(to: out + offset + 4, count: field.count)
            offset += 4 + field.count
        }
        written.pointee = offset
        return ok
    } catch {
        return failed
    }
}

/// One successful evaluation covers every gated key used with the returned context. `stop` is
/// asked every tenth of a second whether the prompt should go away, as when the person has already
/// answered on another device.
@_cdecl("lv_enclave_authenticate")
public func lvEnclaveAuthenticate(
    _ reason: UnsafePointer<CChar>,
    _ timeoutSeconds: Double,
    _ stop: @convention(c) (UnsafeRawPointer?) -> Bool,
    _ flag: UnsafeRawPointer?,
    _ status: UnsafeMutablePointer<Int32>
) -> UnsafeMutableRawPointer? {
    let context = LAContext()
    let done = DispatchSemaphore(value: 0)
    var result = failed
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: String(cString: reason)) { success, error in
        if success {
            result = ok
        } else if let error = error as? LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel: result = cancelled
            default: result = failed
            }
        }
        done.signal()
    }
    let deadline = DispatchTime.now() + timeoutSeconds
    while done.wait(timeout: .now() + 0.1) == .timedOut {
        let stopped = stop(flag)
        guard stopped || DispatchTime.now() >= deadline else { continue }
        context.invalidate()
        _ = done.wait(timeout: .now() + 2)
        status.pointee = stopped ? cancelled : timedOut
        return nil
    }
    status.pointee = result
    guard result == ok else { return nil }
    return Unmanaged.passRetained(context).toOpaque()
}

@_cdecl("lv_enclave_release")
public func lvEnclaveRelease(_ context: UnsafeMutableRawPointer) {
    let context = Unmanaged<LAContext>.fromOpaque(context).takeRetainedValue()
    context.invalidate()
}

/// Writes the P-256 shared secret followed by the ML-KEM shared secret, 64 bytes in all.
@_cdecl("lv_enclave_agree")
public func lvEnclaveAgree(
    _ context: UnsafeMutableRawPointer,
    _ agreementBlob: UnsafePointer<UInt8>, _ agreementBlobLength: Int,
    _ kemBlob: UnsafePointer<UInt8>, _ kemBlobLength: Int,
    _ ephemeral: UnsafePointer<UInt8>, _ ephemeralLength: Int,
    _ ciphertext: UnsafePointer<UInt8>, _ ciphertextLength: Int,
    _ out: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let context = Unmanaged<LAContext>.fromOpaque(context).takeUnretainedValue()
    do {
        let agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: data(agreementBlob, agreementBlobLength),
            authenticationContext: context
        )
        let kem = try SecureEnclave.MLKEM1024.PrivateKey(
            dataRepresentation: data(kemBlob, kemBlobLength),
            authenticationContext: context
        )
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: data(ephemeral, ephemeralLength))
        let classical = try agreement.sharedSecretFromKeyAgreement(with: peer)
        let quantum = try kem.decapsulate(data(ciphertext, ciphertextLength))
        classical.withUnsafeBytes { out.update(from: $0.bindMemory(to: UInt8.self).baseAddress!, count: 32) }
        quantum.withUnsafeBytes { (out + 32).update(from: $0.bindMemory(to: UInt8.self).baseAddress!, count: 32) }
        return ok
    } catch {
        return failed
    }
}

/// Writes a raw P-256 signature (64 bytes) followed by an ML-DSA-87 signature (4627 bytes).
@_cdecl("lv_enclave_sign")
public func lvEnclaveSign(
    _ context: UnsafeMutableRawPointer,
    _ signingBlob: UnsafePointer<UInt8>, _ signingBlobLength: Int,
    _ dsaBlob: UnsafePointer<UInt8>, _ dsaBlobLength: Int,
    _ message: UnsafePointer<UInt8>, _ messageLength: Int,
    _ out: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let context = Unmanaged<LAContext>.fromOpaque(context).takeUnretainedValue()
    do {
        let message = data(message, messageLength)
        let signing = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: data(signingBlob, signingBlobLength),
            authenticationContext: context
        )
        let dsa = try SecureEnclave.MLDSA87.PrivateKey(
            dataRepresentation: data(dsaBlob, dsaBlobLength),
            authenticationContext: context
        )
        let classical = try signing.signature(for: message).rawRepresentation
        let quantum = try dsa.signature(for: message)
        guard classical.count == 64, quantum.count == 4627 else { return failed }
        classical.copyBytes(to: out, count: 64)
        quantum.copyBytes(to: out + 64, count: 4627)
        return ok
    } catch {
        return failed
    }
}

#if os(macOS)
@_cdecl("lv_screen_locked")
public func lvScreenLocked() -> Bool {
    guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return true }
    return session["CGSSessionScreenIsLocked"] as? Bool ?? false
}
#endif
