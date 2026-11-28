package dev.applocker.crypto

enum class CredentialType { PIN, PASSWORD, PATTERN }

/**
 * Minimum-strength rules. Pure Kotlin, no Android dependencies, unit-testable.
 * Pattern encoding: dot indexes 0-8 as characters '0'..'8' in the order drawn.
 */
object CredentialPolicy {
    const val MIN_PIN = 6
    const val MAX_PIN = 16
    const val MIN_PASSWORD = 8
    const val MAX_PASSWORD = 64
    const val MIN_PATTERN = 6

    /** Returns null if acceptable, otherwise a short reason to show the user. */
    fun validate(type: CredentialType, s: CharArray): String? = when (type) {
        CredentialType.PIN -> when {
            s.size < MIN_PIN -> "PIN must be at least $MIN_PIN digits"
            s.size > MAX_PIN -> "PIN must be at most $MAX_PIN digits"
            s.any { it !in '0'..'9' } -> "PIN must contain digits only"
            isTrivial(s) -> "PIN is too easy to guess"
            else -> null
        }
        CredentialType.PASSWORD -> when {
            s.size < MIN_PASSWORD -> "Password must be at least $MIN_PASSWORD characters"
            s.size > MAX_PASSWORD -> "Password must be at most $MAX_PASSWORD characters"
            s.all { it == s[0] } -> "Password is too easy to guess"
            else -> null
        }
        CredentialType.PATTERN -> when {
            s.size < MIN_PATTERN -> "Pattern must connect at least $MIN_PATTERN dots"
            s.any { it !in '0'..'8' } -> "Invalid pattern"
            s.toSet().size != s.size -> "Invalid pattern"
            else -> null
        }
    }

    private fun isTrivial(s: CharArray): Boolean {
        if (s.all { it == s[0] }) return true                       // 000000
        val asc = (1 until s.size).all { s[it] - s[it - 1] == 1 }   // 123456
        val desc = (1 until s.size).all { s[it - 1] - s[it] == 1 }  // 654321
        if (asc || desc) return true
        for (p in 1..s.size / 2) {                                  // 121212, 123123
            if (s.size % p == 0 && s.indices.all { s[it] == s[it % p] }) return true
        }
        return String(s) in setOf("112233", "445566", "778899")
    }
}
