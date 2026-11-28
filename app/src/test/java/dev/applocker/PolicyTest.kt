package dev.applocker

import dev.applocker.crypto.CredentialPolicy
import dev.applocker.crypto.CredentialType.*
import dev.applocker.crypto.FailureState
import dev.applocker.crypto.LockoutPolicy
import org.junit.Assert.*
import org.junit.Test

class PolicyTest {
    private fun v(t: dev.applocker.crypto.CredentialType, s: String) =
        CredentialPolicy.validate(t, s.toCharArray())

    @Test fun pinRules() {
        assertNotNull(v(PIN, "12345"))      // too short
        assertNotNull(v(PIN, "000000"))
        assertNotNull(v(PIN, "123456"))
        assertNotNull(v(PIN, "654321"))
        assertNotNull(v(PIN, "121212"))
        assertNotNull(v(PIN, "123123"))
        assertNotNull(v(PIN, "12345a"))
        assertNull(v(PIN, "280417"))
    }

    @Test fun passwordRules() {
        assertNotNull(v(PASSWORD, "short"))
        assertNotNull(v(PASSWORD, "aaaaaaaa"))
        assertNull(v(PASSWORD, "correct horse"))
    }

    @Test fun patternRules() {
        assertNotNull(v(PATTERN, "01234"))     // 5 dots
        assertNotNull(v(PATTERN, "012341"))    // repeated dot
        assertNotNull(v(PATTERN, "01239x"))
        assertNull(v(PATTERN, "034875"))
    }

    @Test fun delaySchedule() {
        assertEquals(0L, LockoutPolicy.delayForFailures(4))
        assertEquals(30_000L, LockoutPolicy.delayForFailures(5))
        assertEquals(3_600_000L, LockoutPolicy.delayForFailures(9))
        assertEquals(3_600_000L, LockoutPolicy.delayForFailures(50))
    }

    @Test fun clockTamperingCannotShortenDelay() {
        val s = FailureState(5, 30_000, lockedAtWall = 1_000_000, lockedAtElapsed = 500, bootId = 7)
        // user moves wall clock forward 1 day, only 10 s really passed
        assertEquals(20_000L, LockoutPolicy.remainingMs(s, 1_000_000 + 86_400_000, 10_500, 7))
        // after reboot, wall clock rolled back -> full delay restarts
        assertEquals(30_000L, LockoutPolicy.remainingMs(s, 900_000, 100, 8))
        // after reboot, normal clock
        assertEquals(10_000L, LockoutPolicy.remainingMs(s, 1_020_000, 100, 8))
    }
}
