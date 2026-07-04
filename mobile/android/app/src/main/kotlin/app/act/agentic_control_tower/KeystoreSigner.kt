package app.act.agentic_control_tower

import android.os.Build
import android.util.Log
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Android Keystore equivalent of the iOS Secure Enclave signer, on the same
 * `act/secure_enclave` MethodChannel so the Dart layer is platform-agnostic.
 *
 * Generates a non-exportable ECDSA P-256 (secp256r1) key in the Android Keystore
 * with setUserAuthenticationRequired(true) (StrongBox-preferred, TEE fallback).
 * Signing is gated by a BiometricPrompt (BIOMETRIC_STRONG or device credential);
 * the private key never leaves the keystore. Public key is exported as an X9.63
 * uncompressed point and signatures are DER ECDSA-SHA256 — exactly what the gateway
 * verifies. Honest reporting: `hardwareBacked` reflects the real KeyInfo security
 * level, so a software-keymaster emulator is never reported as hardware-backed.
 */
class KeystoreSigner(private val activityProvider: () -> FragmentActivity?) {
    companion object {
        const val CHANNEL = "act/secure_enclave"
        private const val KEY_ALIAS = "act_device_signing_key"
        private const val KEYSTORE = "AndroidKeyStore"
        // Key-level auth validity window; the Dart-supplied allowReuseSeconds decides
        // whether to re-prompt within it (mirrors the iOS reuse behaviour).
        private const val AUTH_WINDOW_SECONDS = 300
    }

    private var lastAuthAtMs: Long = 0L

    // Only one BiometricPrompt can be active per activity; androidx.biometric
    // silently ignores a second authenticate() call while one is showing, which
    // would leave that call's MethodChannel result (and its Dart future) hanging
    // forever. Serialize instead: while a prompt is up, queue sign requests and
    // settle them when the prompt resolves (signing within the fresh auth
    // window on success, failing them on error). Main-thread only.
    private var promptActive: Boolean = false
    private val queuedSigns = ArrayDeque<Pair<ByteArray, MethodChannel.Result>>()

    fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "isAvailable" -> result.success(true)
            "status" -> handleStatus(result)
            "generateKey" -> handleGenerateKey(result)
            "sign" -> handleSign(call, result)
            "clearKey" -> handleClear(result)
            else -> result.notImplemented()
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun handleGenerateKey(result: MethodChannel.Result) {
        try {
            val ks = keyStore()
            if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)

            fun buildSpec(strongBox: Boolean): KeyGenParameterSpec {
                val builder = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    builder.setUserAuthenticationParameters(
                        AUTH_WINDOW_SECONDS,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                    )
                } else {
                    @Suppress("DEPRECATION")
                    builder.setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_SECONDS)
                }
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    builder.setIsStrongBoxBacked(true)
                }
                return builder.build()
            }

            val tryStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
            val publicKey: ECPublicKey = try {
                generate(buildSpec(tryStrongBox))
            } catch (e: Exception) {
                // StrongBox unavailable on this device -> fall back to TEE.
                if (tryStrongBox) generate(buildSpec(false)) else throw e
            }

            val hw = hardwareInfo()
            result.success(
                mapOf(
                    "publicKey" to b64url(encodeX963(publicKey)),
                    "backend" to hw.second,
                    "hardwareBacked" to hw.first,
                ),
            )
        } catch (e: Exception) {
            result.error("generate_failed", e.message, null)
        }
    }

    private fun generate(spec: KeyGenParameterSpec): ECPublicKey {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
        kpg.initialize(spec)
        return kpg.generateKeyPair().public as ECPublicKey
    }

    private fun handleSign(call: MethodCall, result: MethodChannel.Result) {
        val dataB64 = call.argument<String>("data")
        if (dataB64 == null) {
            result.error("bad_arguments", "missing data", null)
            return
        }
        val data = Base64.decode(dataB64, Base64.DEFAULT)
        val reason = call.argument<String>("reason") ?: "Authorize clearance decision"
        val allowReuse = (call.argument<Double>("allowReuseSeconds") ?: 0.0)

        val nowMs = System.currentTimeMillis()
        val withinWindow =
            allowReuse > 0 && lastAuthAtMs > 0 && (nowMs - lastAuthAtMs) < allowReuse * 1000
        if (withinWindow) {
            Log.i("KeystoreSigner", "sign: within window, reason=$reason")
            signNow(data, result)
            return
        }

        if (promptActive) {
            Log.i("KeystoreSigner", "sign: prompt active, queueing (depth=${queuedSigns.size + 1}) reason=$reason")
            queuedSigns.addLast(data to result)
            return
        }

        val activity = activityProvider()
        if (activity == null) {
            result.error("no_activity", "no foreground activity for biometric prompt", null)
            return
        }
        Log.i("KeystoreSigner", "sign: showing prompt, reason=$reason")
        promptActive = true
        activity.runOnUiThread {
            val prompt = BiometricPrompt(
                activity,
                ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                        Log.i("KeystoreSigner", "prompt success; draining ${queuedSigns.size} queued")
                        lastAuthAtMs = System.currentTimeMillis()
                        promptActive = false
                        signNow(data, result)
                        drainQueuedSigns(authSucceeded = true)
                    }

                    override fun onAuthenticationError(code: Int, msg: CharSequence) {
                        Log.i("KeystoreSigner", "prompt error code=$code msg=$msg; failing ${queuedSigns.size} queued")
                        promptActive = false
                        result.error("auth_failed", msg.toString(), null)
                        drainQueuedSigns(authSucceeded = false, message = msg.toString())
                    }
                },
            )
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Agentic Control Tower")
                .setSubtitle(reason)
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
                .build()
            prompt.authenticate(info)
        }
    }

    /** Settle sign requests that arrived while a BiometricPrompt was showing. */
    private fun drainQueuedSigns(authSucceeded: Boolean, message: String = "") {
        while (queuedSigns.isNotEmpty()) {
            val (data, result) = queuedSigns.removeFirst()
            if (authSucceeded) {
                signNow(data, result)
            } else {
                result.error("auth_failed", message, null)
            }
        }
    }

    private fun signNow(data: ByteArray, result: MethodChannel.Result) {
        try {
            val ks = keyStore()
            val privateKey = ks.getKey(KEY_ALIAS, null) as PrivateKey
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(privateKey)
            signature.update(data)
            result.success(b64url(signature.sign()))
        } catch (e: Exception) {
            Log.w("KeystoreSigner", "signNow failed: ${e.message}")
            result.error("sign_failed", e.message, null)
        }
    }

    private fun handleStatus(result: MethodChannel.Result) {
        val ks = keyStore()
        val hasKey = ks.containsAlias(KEY_ALIAS)
        val hw = if (hasKey) hardwareInfo() else Pair(false, "none")
        var biometryAvailable = false
        val activity = activityProvider()
        if (activity != null) {
            val canAuth = BiometricManager.from(activity).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
            biometryAvailable = canAuth == BiometricManager.BIOMETRIC_SUCCESS
        }
        result.success(
            mapOf(
                "secureEnclaveAvailable" to true,
                "hasKey" to hasKey,
                "backend" to (if (hasKey) hw.second else "android_keystore"),
                "hardwareBacked" to hw.first,
                "userPresenceRequired" to true,
                "privateKeyExportable" to false,
                "biometryAvailable" to biometryAvailable,
                "biometryType" to "android_biometric",
            ),
        )
    }

    private fun handleClear(result: MethodChannel.Result) {
        try {
            val ks = keyStore()
            if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)
            lastAuthAtMs = 0L
            result.success(null)
        } catch (e: Exception) {
            result.error("clear_failed", e.message, null)
        }
    }

    /** Returns (isHardwareBacked, backendLabel) from the real KeyInfo security level. */
    private fun hardwareInfo(): Pair<Boolean, String> {
        return try {
            val ks = keyStore()
            val key = ks.getKey(KEY_ALIAS, null) as? PrivateKey ?: return Pair(false, "none")
            val factory = KeyFactory.getInstance(key.algorithm, KEYSTORE)
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX ->
                        Pair(true, "android_strongbox_p256")
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                        Pair(true, "android_tee_p256")
                    else -> Pair(false, "android_software_p256_dev")
                }
            } else {
                @Suppress("DEPRECATION")
                val hw = info.isInsideSecureHardware
                Pair(hw, if (hw) "android_tee_p256" else "android_software_p256_dev")
            }
        } catch (e: Exception) {
            Pair(false, "android_unknown")
        }
    }

    private fun encodeX963(publicKey: ECPublicKey): ByteArray {
        val x = to32(publicKey.w.affineX)
        val y = to32(publicKey.w.affineY)
        return ByteArray(1) { 0x04 } + x + y
    }

    private fun to32(value: BigInteger): ByteArray {
        var bytes = value.toByteArray()
        // Strip a leading sign byte, or left-pad to a fixed 32-byte field element.
        if (bytes.size > 32) bytes = bytes.copyOfRange(bytes.size - 32, bytes.size)
        if (bytes.size < 32) {
            val padded = ByteArray(32)
            System.arraycopy(bytes, 0, padded, 32 - bytes.size, bytes.size)
            bytes = padded
        }
        return bytes
    }

    private fun b64url(data: ByteArray): String =
        Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}
