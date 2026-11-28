package dev.applocker.data

import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import dev.applocker.crypto.CredentialHasher
import dev.applocker.crypto.CredentialPolicy
import dev.applocker.crypto.CredentialType
import dev.applocker.crypto.FailureState
import dev.applocker.crypto.LockoutPolicy

sealed interface AuthResult {
    object Success : AuthResult
    object Wrong : AuthResult
    class Locked(val remainingMs: Long) : AuthResult
    object NotConfigured : AuthResult
    /** Config unreadable. Caller must decide the fail-closed/fail-open policy (open decision). */
    object StoreCorrupt : AuthResult
}

/**
 * Central place for enrolling and verifying per-app credentials.
 * All calls are blocking (PBKDF2 + disk): run them on a background thread.
 *
 * Verification order is security-critical:
 *   1. refuse if a lockout is active (per-app OR global)
 *   2. persist the incremented failure counter  <-- BEFORE checking the secret
 *   3. check the secret
 *   4. on success, persist the reset counters
 * Killing the process between 2 and 3 therefore cannot reset or avoid the penalty.
 */
class AuthRepository(private val context: Context) {
    private val store = SecureStore(context)
    private val lock = Any()

    private fun bootId() =
        Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, 0)

    private fun load(): AppConfig? = when (val s = store.read()) {
        StoreState.Empty -> AppConfig()
        is StoreState.Ok -> try { ConfigCodec.decode(s.plain) } catch (_: Exception) { null }
        StoreState.Corrupt -> null
    }

    private fun save(c: AppConfig) = store.write(ConfigCodec.encode(c))

    /** Returns null on success, or a user-facing reason. Replaces any existing entry. */
    fun enroll(
        pkg: String, type: CredentialType, secret: CharArray,
        relock: RelockPolicy = RelockPolicy.SCREEN_OFF, relockMinutes: Int = 0
    ): String? = synchronized(lock) {
        CredentialPolicy.validate(type, secret)?.let { return it }
        val cfg = load() ?: return "Stored data is unreadable"
        val entry = AppLockEntry(pkg, CredentialHasher.create(type, secret), relock, relockMinutes)
        save(AppConfig(cfg.version, cfg.globalFailure, cfg.apps + (pkg to entry)))
        null
    }

    fun verifyApp(pkg: String, secret: CharArray): AuthResult = synchronized(lock) {
        val cfg = load() ?: return AuthResult.StoreCorrupt
        val entry = cfg.apps[pkg] ?: return AuthResult.NotConfigured

        val wall = System.currentTimeMillis()
        val elapsed = SystemClock.elapsedRealtime()
        val boot = bootId()

        val remaining = maxOf(
            LockoutPolicy.remainingMs(entry.failure, wall, elapsed, boot),
            LockoutPolicy.remainingMs(cfg.globalFailure, wall, elapsed, boot)
        )
        if (remaining > 0) return AuthResult.Locked(remaining)

        // Persist the attempt first.
        val pre = AppConfig(
            cfg.version,
            LockoutPolicy.registerAttempt(cfg.globalFailure, wall, elapsed, boot),
            cfg.apps + (pkg to entry.copy(failure = LockoutPolicy.registerAttempt(entry.failure, wall, elapsed, boot)))
        )
        save(pre)

        if (CredentialHasher.verify(secret, entry.credential)) {
            save(AppConfig(pre.version, FailureState(), pre.apps + (pkg to entry.copy(failure = FailureState()))))
            AuthResult.Success
        } else {
            val after = maxOf(
                LockoutPolicy.remainingMs(pre.apps.getValue(pkg).failure, wall, elapsed, boot),
                LockoutPolicy.remainingMs(pre.globalFailure, wall, elapsed, boot)
            )
            if (after > 0) AuthResult.Locked(after) else AuthResult.Wrong
        }
    }
}
