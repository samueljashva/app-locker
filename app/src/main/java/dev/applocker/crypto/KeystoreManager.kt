package dev.applocker.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Two non-exportable Android Keystore keys:
 *  - AES-256-GCM: encrypts the config file at rest.
 *  - HMAC-SHA256: binds every PIN hash to this device (a copied config is useless elsewhere).
 * StrongBox (dedicated secure chip) is used when available, else the normal TEE/hardware Keystore.
 * No user-authentication binding: keys must work while the locker verifies a PIN.
 */
object KeystoreManager {
    private const val PROVIDER = "AndroidKeyStore"
    private const val CONFIG_ALIAS = "applocker.config.aes.v1"
    private const val HMAC_ALIAS = "applocker.verify.hmac.v1"

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    @Synchronized
    fun configKey(): SecretKey =
        existing(CONFIG_ALIAS) ?: generate(
            CONFIG_ALIAS, KeyProperties.KEY_ALGORITHM_AES,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ) {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setKeySize(256)
            setRandomizedEncryptionRequired(true)
        }

    @Synchronized
    fun hmacKey(): SecretKey =
        existing(HMAC_ALIAS) ?: generate(
            HMAC_ALIAS, KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
            KeyProperties.PURPOSE_SIGN
        ) {
            setDigests(KeyProperties.DIGEST_SHA256)
        }

    private fun existing(alias: String): SecretKey? =
        keyStore().getKey(alias, null) as? SecretKey

    private fun generate(
        alias: String,
        algorithm: String,
        purposes: Int,
        configure: KeyGenParameterSpec.Builder.() -> Unit
    ): SecretKey {
        fun build(strongBox: Boolean): SecretKey {
            val b = KeyGenParameterSpec.Builder(alias, purposes)
            b.configure()
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                b.setIsStrongBoxBacked(true)
            }
            val gen = KeyGenerator.getInstance(algorithm, PROVIDER)
            gen.init(b.build())
            return gen.generateKey()
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try { return build(strongBox = true) } catch (_: Exception) { /* fall back below */ }
        }
        return build(strongBox = false)
    }
}
