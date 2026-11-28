package dev.applocker.data

import android.content.Context
import android.util.AtomicFile
import dev.applocker.crypto.KeystoreManager
import java.io.File
import java.io.IOException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

sealed interface StoreState {
    object Empty : StoreState                       // first run, nothing saved yet
    class Ok(val plain: ByteArray) : StoreState
    /** File exists but cannot be decrypted (key lost, file tampered or damaged). */
    object Corrupt : StoreState
}

/**
 * Single encrypted file: [12-byte IV][AES-256-GCM ciphertext+tag].
 * Atomic writes (temp file + rename) so a crash mid-write cannot destroy the config.
 */
class SecureStore(context: Context) {
    private val file = AtomicFile(File(context.filesDir, "config.bin"))

    fun read(): StoreState {
        if (!file.baseFile.exists()) return StoreState.Empty
        return try {
            val raw = file.readFully()
            if (raw.size <= IV_BYTES) return StoreState.Corrupt
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(
                Cipher.DECRYPT_MODE, KeystoreManager.configKey(),
                GCMParameterSpec(TAG_BITS, raw, 0, IV_BYTES)
            )
            cipher.updateAAD(AAD)
            StoreState.Ok(cipher.doFinal(raw, IV_BYTES, raw.size - IV_BYTES))
        } catch (e: Exception) {
            StoreState.Corrupt
        }
    }

    @Throws(IOException::class)
    fun write(plain: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, KeystoreManager.configKey())
        cipher.updateAAD(AAD)
        val iv = cipher.iv
        val ct = cipher.doFinal(plain)
        val out = file.startWrite()
        try {
            out.write(iv)
            out.write(ct)
            file.finishWrite(out)
        } catch (e: IOException) {
            file.failWrite(out)
            throw e
        }
    }

    private companion object {
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BITS = 128
        val AAD = "applocker-config-v1".toByteArray()
    }
}
