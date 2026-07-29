import CryptoKit
import Flutter
import Foundation
import LocalAuthentication
import Security

/// Native Secure-Enclave signing for the mobile_signed clearance channel.
///
/// A genuine hardware-backed key on Apple silicon is ECDSA P-256 generated INSIDE
/// the Secure Enclave: the private key is non-exportable and every signature is
/// gated by user presence (Face ID / Touch ID / device passcode) via the key's
/// SecAccessControl. The public key is exported as an X9.63 uncompressed point and
/// signatures are DER-encoded — exactly what the gateway's additive P-256 path
/// verifies.
///
/// On the Simulator (which has no Secure Enclave) the module HONESTLY degrades to a
/// software P-256 key and reports `hardwareBacked: false`. It still drives a
/// LocalAuthentication prompt so the biometric UX can be exercised, but it is never
/// reported as enclave-backed.
@available(iOS 13.0, *)
final class SecureEnclaveSigner {
  static let channelName = "act/secure_enclave"

  private let keychainService = "com.act.secure_enclave"
  private let keychainAccount = "device_signing_key"

  // A short-lived authenticated context is reused within its window so that the
  // two signatures a decision produces (per-decision payload + HMCP transport)
  // share a single user-presence prompt. Outside the window, signing prompts
  // again — so each clearance decision still requires a fresh presence check.
  private var cachedContext: LAContext?
  private var cachedContextAt: Date?
  // Whether the cached context has already passed a presence check. Only the
  // Simulator's software path consults this (see handleSign): real hardware lets
  // LocalAuthentication enforce the reuse window itself.
  private var cachedContextAuthenticated = false
  private let cacheLock = NSLock()
  // 1-byte marker stored ahead of the key blob: 0x01 = enclave, 0x00 = software.
  private let enclaveMarker: UInt8 = 0x01
  private let softwareMarker: UInt8 = 0x00

  /// The single source of truth for "can this build actually use the Secure Enclave".
  ///
  /// `SecureEnclave.isAvailable` returns **true on the iOS Simulator**, where the
  /// enclave does not exist: key generation then fails with LocalAuthentication
  /// -1020 ("This call is not supported on iOS Simulator") and — worse — status
  /// reporting would claim `secure_enclave_p256` / `hardwareBacked: true` on a
  /// machine with no hardware key protection at all. The compile-time
  /// `targetEnvironment(simulator)` check makes that impossible.
  ///
  /// Every enclave-capability decision in this file goes through this property.
  private static var secureEnclaveUsable: Bool {
    #if targetEnvironment(simulator)
      return false
    #else
      return SecureEnclave.isAvailable
    #endif
  }

  static func register(with registry: FlutterPluginRegistry) {
    guard let registrar = registry.registrar(forPlugin: "SecureEnclaveSigner") else { return }
    let channel = FlutterMethodChannel(
      name: channelName, binaryMessenger: registrar.messenger())
    let instance = SecureEnclaveSigner()
    channel.setMethodCallHandler { call, result in
      instance.handle(call, result: result)
    }
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "isAvailable":
      result(Self.secureEnclaveUsable)
    case "isSupported":
      // The native P-256 signer module is present. True wherever this code runs
      // (iOS device and Simulator alike) — it says nothing about hardware
      // backing; ask `isAvailable`/`status` for that.
      result(true)
    case "status":
      handleStatus(result)
    case "generateKey":
      handleGenerateKey(call, result)
    case "sign":
      handleSign(call, result)
    case "clearKey":
      handleClear(result)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  // MARK: - Status

  private func handleStatus(_ result: @escaping FlutterResult) {
    let available = Self.secureEnclaveUsable
    let stored = loadKey()
    let isEnclave = stored?.isEnclave ?? available
    let context = LAContext()
    var authError: NSError?
    let biometryAvailable = context.canEvaluatePolicy(
      .deviceOwnerAuthentication, error: &authError)
    result([
      "secureEnclaveAvailable": available,
      "hasKey": stored != nil,
      "backend": isEnclave ? "secure_enclave_p256" : "software_p256_dev",
      "hardwareBacked": stored != nil ? stored!.isEnclave : available,
      "userPresenceRequired": true,
      "privateKeyExportable": stored != nil ? !stored!.isEnclave : !available,
      "biometryAvailable": biometryAvailable,
      "biometryType": biometryTypeName(context),
    ])
  }

  // MARK: - Generate

  private func handleGenerateKey(
    _ call: FlutterMethodCall, _ result: @escaping FlutterResult
  ) {
    var accessError: Unmanaged<CFError>?
    guard
      let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .userPresence],
        &accessError)
    else {
      result(flutterError("access_control", accessError))
      return
    }

    // The two generation paths are mutually exclusive at COMPILE time, not at
    // runtime. A device build contains only the enclave path: there is no
    // software-key code to fall back to, so a Secure Enclave failure on real
    // hardware stays a hard failure and can never silently downgrade the
    // clearance channel to an exportable key.
    do {
      #if targetEnvironment(simulator)
        // Simulator has no Secure Enclave. Honest software fallback so the
        // mobile_signed P-256 channel can be exercised end to end; always
        // reported as software / not hardware-backed.
        _ = access
        let key = P256.Signing.PrivateKey()
        try persist(blob: key.rawRepresentation, isEnclave: false)
        result([
          "publicKey": base64url(key.publicKey.x963Representation),
          "backend": "software_p256_dev",
          "hardwareBacked": false,
        ])
      #else
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try persist(blob: key.dataRepresentation, isEnclave: true)
        result([
          "publicKey": base64url(key.publicKey.x963Representation),
          "backend": "secure_enclave_p256",
          "hardwareBacked": true,
        ])
      #endif
    } catch {
      result(FlutterError(code: "generate_failed", message: "\(error)", details: nil))
    }
  }

  // MARK: - Sign

  private func handleSign(
    _ call: FlutterMethodCall, _ result: @escaping FlutterResult
  ) {
    guard let args = call.arguments as? [String: Any],
      let dataB64 = args["data"] as? String,
      let data = Data(base64Encoded: dataB64)
    else {
      result(FlutterError(code: "bad_arguments", message: "missing data", details: nil))
      return
    }
    let reason = (args["reason"] as? String) ?? "Authorize clearance decision"
    let allowReuse = (args["allowReuseSeconds"] as? Double) ?? 0

    guard let stored = loadKey() else {
      result(FlutterError(code: "no_key", message: "no signing key enrolled", details: nil))
      return
    }

    let (context, presenceEstablished) = authenticationContext(
      reason: reason, allowReuse: allowReuse)

    // Sign off the main thread; the enclave/biometric evaluation can block.
    DispatchQueue.global(qos: .userInitiated).async {
      do {
        let signatureDer: Data
        if stored.isEnclave {
          let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: stored.blob, authenticationContext: context)
          signatureDer = try key.signature(for: data).derRepresentation
        } else {
          // Software fallback still drives an auth prompt so the gate is exercised.
          //
          // On the Simulator LocalAuthentication ignores
          // `touchIDAuthenticationAllowableReuseDuration`, so a reused context
          // would re-prompt for EVERY signed request and overlapping evaluations
          // cancel each other with LAError -4 ("Canceled by another
          // authentication"). Honour the reuse window here so reuse behaves as it
          // does on real hardware. A clearance decision passes allowReuse == 0,
          // which never yields a reused context — so decisions always prompt.
          #if targetEnvironment(simulator)
            if !presenceEstablished {
              try self.evaluatePresence(context: context, reason: reason)
              self.markPresenceEstablished(for: context)
            }
          #else
            _ = presenceEstablished
            try self.evaluatePresence(context: context, reason: reason)
          #endif
          let key = try P256.Signing.PrivateKey(rawRepresentation: stored.blob)
          signatureDer = try key.signature(for: data).derRepresentation
        }
        let encoded = self.base64url(signatureDer)
        DispatchQueue.main.async { result(encoded) }
      } catch {
        DispatchQueue.main.async {
          result(
            FlutterError(
              code: "sign_failed", message: "\(error)", details: nil))
        }
      }
    }
  }

  /// Return a context to authenticate the signature. When [allowReuse] > 0 a
  /// recently authenticated context is reused within its window (single prompt
  /// for a decision's two signatures); otherwise a fresh context is created.
  ///
  /// `presenceEstablished` is true only when this returned a cached context that
  /// has already passed a presence check inside its reuse window.
  private func authenticationContext(reason: String, allowReuse: Double) -> (
    context: LAContext, presenceEstablished: Bool
  ) {
    cacheLock.lock()
    defer { cacheLock.unlock() }
    if allowReuse > 0,
      let cached = cachedContext,
      let at = cachedContextAt,
      Date().timeIntervalSince(at) < allowReuse {
      return (cached, cachedContextAuthenticated)
    }
    let context = LAContext()
    context.localizedReason = reason
    if allowReuse > 0 {
      context.touchIDAuthenticationAllowableReuseDuration = allowReuse
      cachedContext = context
      cachedContextAt = Date()
    } else {
      cachedContext = nil
      cachedContextAt = nil
    }
    cachedContextAuthenticated = false
    return (context, false)
  }

  /// Record that [context] has passed a presence check, so a reuse-window hit
  /// does not have to prompt again.
  private func markPresenceEstablished(for context: LAContext) {
    cacheLock.lock()
    defer { cacheLock.unlock() }
    if cachedContext === context {
      cachedContextAuthenticated = true
    }
  }

  private func evaluatePresence(context: LAContext, reason: String) throws {
    let semaphore = DispatchSemaphore(value: 0)
    var evalError: Error?
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) {
      success, error in
      if !success { evalError = error ?? NSError(domain: "act.auth", code: -1) }
      semaphore.signal()
    }
    semaphore.wait()
    if let evalError { throw evalError }
  }

  // MARK: - Clear

  private func handleClear(_ result: @escaping FlutterResult) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: keychainService,
      kSecAttrAccount as String: keychainAccount,
    ]
    SecItemDelete(query as CFDictionary)
    cacheLock.lock()
    cachedContext = nil
    cachedContextAt = nil
    cachedContextAuthenticated = false
    cacheLock.unlock()
    result(nil)
  }

  // MARK: - Keychain persistence

  private struct StoredKey {
    let blob: Data
    let isEnclave: Bool
  }

  private func persist(blob: Data, isEnclave: Bool) throws {
    var payload = Data([isEnclave ? enclaveMarker : softwareMarker])
    payload.append(blob)
    let base: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: keychainService,
      kSecAttrAccount as String: keychainAccount,
    ]
    SecItemDelete(base as CFDictionary)
    var attributes = base
    attributes[kSecValueData as String] = payload
    attributes[kSecAttrAccessible as String] =
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    let status = SecItemAdd(attributes as CFDictionary, nil)
    if status != errSecSuccess {
      throw NSError(domain: "act.keychain", code: Int(status), userInfo: nil)
    }
  }

  private func loadKey() -> StoredKey? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: keychainService,
      kSecAttrAccount as String: keychainAccount,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data, data.count > 1 else {
      return nil
    }
    let marker = data[data.startIndex]
    let blob = data.subdata(in: (data.startIndex + 1)..<data.endIndex)
    return StoredKey(blob: blob, isEnclave: marker == enclaveMarker)
  }

  // MARK: - Helpers

  private func base64url(_ data: Data) -> String {
    return data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private func biometryTypeName(_ context: LAContext) -> String {
    switch context.biometryType {
    case .faceID: return "faceID"
    case .touchID: return "touchID"
    default: return "none"
    }
  }

  private func flutterError(_ code: String, _ error: Unmanaged<CFError>?) -> FlutterError {
    let message = error.map { "\($0.takeRetainedValue())" } ?? "unknown error"
    return FlutterError(code: code, message: message, details: nil)
  }
}
