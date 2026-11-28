package dev.applocker.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/** What is persisted per credential. Never contains the secret itself. */
class StoredCredential(
    val type: CredentialType,
    val salt: ByteArray,
    val iterations: Int,
    val tag: ByteArray
)

/**
 * tag = HMAC-SHA256( keystoreKey, PBKDF2-HMAC-SHA256(secret, salt, iterations) )
 *
 * - PBKDF2 makes each guess expensive if someone has the file.
 * - The Keystore HMAC makes the file worthless off this device (key cannot be exported).
 * - Verification uses a constant-time comparison.
 * Slow by design (~0.3-1 s on typical phones): ALWAYS call off the main thread.
 */
object CredentialHasher {
    const val DEFAULT_ITERATIONS = 600_000
    private const val SALT_BYTES = 16
    private const val KEY_BITS = 256
    private val random = SecureRandom()

    fun create(type: CredentialType, secret: CharArray): StoredCredential {
        val salt = ByteArray(SALT_BYTES).also { random.nextBytes(it) }
        return StoredCredential(type, salt, DEFAULT_ITERATIONS, derive(secret, salt, DEFAULT_ITERATIONS))
    }

    fun verify(secret: CharArray, stored: StoredCredential): Boolean {
        val candidate = derive(secret, stored.salt, stored.iterations)
        return try {
            MessageDigest.isEqual(candidate, stored.tag)
        } finally {
            candidate.fill(0)
        }
    }

    private fun derive(secret: CharArray, salt: ByteArray, iterations: Int): ByteArray {
        val spec = PBEKeySpec(secret, salt, iterations, KEY_BITS)
        val raw = try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
        try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(KeystoreManager.hmacKey())
            return mac.doFinal(raw)
        } finally {
            raw.fill(0)
        }
    }
}
