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
  // Whether the cached context has already passed a presence check. The
  // Simulator's software path consults this to skip a redundant prompt (see
  // performSign); on real hardware LocalAuthentication enforces the reuse
  // window itself and this is bookkeeping only — the sign queue uses it to
  // tell "this operation owned the (failed) evaluation" from "signing failed
  // under an already-authenticated context" when deciding whether a failure
  // must fail the whole queued batch.
  private var cachedContextAuthenticated = false
  private let cacheLock = NSLock()
  // 1-byte marker stored ahead of the key blob: 0x01 = enclave, 0x00 = software.
  private let enclaveMarker: UInt8 = 0x01
  private let softwareMarker: UInt8 = 0x00

  // Serialize sign operations — the iOS twin of the Android KeystoreSigner
  // queue-and-drain fix (8cbf226). Overlapping LAContext evaluations cancel
  // each other with LAError -4 ("Canceled by another authentication"): on a
  // device the enclave key's user-presence gate runs one evaluation per
  // signature, so a launch burst of concurrent signed GETs killed every
  // in-flight sign and left the MethodChannel results unsettled — Dart futures
  // hung forever and no request ever reached the gateway. While one sign
  // operation is in flight, later requests queue here; when it resolves the
  // queue drains strictly serially: a request whose reuse window covers the
  // just-authenticated context signs without prompting, an allowReuse == 0
  // request (clearance decision) runs its OWN fresh evaluation — one at a
  // time, never concurrently. A failed evaluation fails the whole queued batch
  // with auth_failed so every future settles.
  private struct PendingSign {
    let data: Data
    let reason: String
    let allowReuse: Double
    let stored: StoredKey
    let result: FlutterResult
  }
  private var signQueue: [PendingSign] = []
  private var signInFlight = false
  private let signStateLock = NSLock()

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

    let request = PendingSign(
      data: data, reason: reason, allowReuse: allowReuse, stored: stored, result: result)

    // Never start a second evaluation while one is in flight (see PendingSign).
    signStateLock.lock()
    if signInFlight {
      NSLog(
        "SecureEnclaveSigner: sign in flight, queueing (depth=%d) reason=%@",
        signQueue.count + 1, reason)
      signQueue.append(request)
      signStateLock.unlock()
      return
    }
    signInFlight = true
    signStateLock.unlock()
    performSign(request)
  }

  /// Run one sign operation. Exactly one is in flight at any time
  /// (`signInFlight`); the operation's resolution settles this request's
  /// result and then drains the queue through `finishSign`.
  private func performSign(_ request: PendingSign) {
    let (context, presenceEstablished) = authenticationContext(
      reason: request.reason, allowReuse: request.allowReuse)

    // Sign off the main thread; the enclave/biometric evaluation can block.
    DispatchQueue.global(qos: .userInitiated).async {
      do {
        let signatureDer: Data
        if request.stored.isEnclave {
          let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: request.stored.blob, authenticationContext: context)
          signatureDer = try key.signature(for: request.data).derRepresentation
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
              try self.evaluatePresence(context: context, reason: request.reason)
              self.markPresenceEstablished(for: context)
            }
          #else
            _ = presenceEstablished
            try self.evaluatePresence(context: context, reason: request.reason)
          #endif
          let key = try P256.Signing.PrivateKey(rawRepresentation: request.stored.blob)
          signatureDer = try key.signature(for: request.data).derRepresentation
        }
        // Bookkeeping only: record that this context passed its presence check
        // so queue drains know the window is warm. On hardware,
        // LocalAuthentication still enforces the reuse window itself, and an
        // allowReuse == 0 request never receives a cached context at all.
        self.markPresenceEstablished(for: context)
        let encoded = self.base64url(signatureDer)
        DispatchQueue.main.async { request.result(encoded) }
        self.finishSign(evaluationFailed: false, message: "")
      } catch {
        // If this operation owned a fresh presence evaluation (or the error is
        // auth-shaped), each queued request would re-prompt on drain — fail the
        // whole batch with auth_failed instead, mirroring the Android fix.
        let authError = self.isAuthenticationError(error)
        let evaluationFailed = !presenceEstablished || authError
        if evaluationFailed { self.clearCachedContext(ifMatches: context) }
        DispatchQueue.main.async {
          request.result(
            FlutterError(
              code: authError ? "auth_failed" : "sign_failed",
              message: "\(error)", details: nil))
        }
        self.finishSign(evaluationFailed: evaluationFailed, message: "\(error)")
      }
    }
  }

  /// Called exactly once when the in-flight sign operation resolves — every
  /// path through `performSign` reaches here, so every queued MethodChannel
  /// result settles. On a failed evaluation the whole pending batch fails with
  /// auth_failed (the Android KeystoreSigner drain does the same); otherwise
  /// the next queued request starts — signing under the just-authenticated
  /// context when its reuse window permits, or running its own fresh
  /// evaluation (allowReuse == 0) — never concurrently.
  private func finishSign(evaluationFailed: Bool, message: String) {
    signStateLock.lock()
    if evaluationFailed {
      let failed = signQueue
      signQueue.removeAll()
      signInFlight = false
      signStateLock.unlock()
      if !failed.isEmpty {
        NSLog("SecureEnclaveSigner: evaluation failed; failing %d queued sign(s)", failed.count)
        DispatchQueue.main.async {
          for pending in failed {
            pending.result(FlutterError(code: "auth_failed", message: message, details: nil))
          }
        }
      }
      return
    }
    guard !signQueue.isEmpty else {
      signInFlight = false
      signStateLock.unlock()
      return
    }
    let next = signQueue.removeFirst()
    let remaining = signQueue.count
    signStateLock.unlock()
    NSLog(
      "SecureEnclaveSigner: draining queued sign (remaining=%d) reason=%@",
      remaining, next.reason)
    performSign(next)
  }

  /// Best-effort classification of a sign failure as an authentication
  /// (user-presence) failure rather than a crypto/keychain one. Walks the
  /// underlying-error chain for LocalAuthentication and Security auth codes.
  private func isAuthenticationError(_ error: Error) -> Bool {
    var current: NSError? = error as NSError
    var depth = 0
    while let nsError = current, depth < 4 {
      if nsError.domain == LAError.errorDomain { return true }
      if nsError.domain == NSOSStatusErrorDomain,
        nsError.code == Int(errSecAuthFailed)
          || nsError.code == Int(errSecUserCanceled)
          || nsError.code == Int(errSecInteractionNotAllowed)
      {
        return true
      }
      current = nsError.userInfo[NSUnderlyingErrorKey] as? NSError
      depth += 1
    }
    return false
  }

  /// Drop the cached context after [context]'s evaluation failed, so the next
  /// sign starts from a clean prompt rather than a context that has a failed
  /// evaluation on record.
  private func clearCachedContext(ifMatches context: LAContext) {
    cacheLock.lock()
    defer { cacheLock.unlock() }
    if cachedContext === context {
      cachedContext = nil
      cachedContextAt = nil
      cachedContextAuthenticated = false
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
