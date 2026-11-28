package dev.applocker.crypto

import kotlin.math.max

/** Persisted brute-force state. One instance per locked app, plus one global. */
data class FailureState(
    val failures: Int = 0,
    val delayMs: Long = 0,
    val lockedAtWall: Long = 0,     // System.currentTimeMillis() when delay began
    val lockedAtElapsed: Long = 0,  // SystemClock.elapsedRealtime() when delay began
    val bootId: Int = 0             // Settings.Global.BOOT_COUNT at that time
)

/**
 * Escalating delay schedule. Pure functions so they can be unit-tested.
 * 1-4 failures: no delay. Then 30s, 1m, 5m, 15m, and 1h for every further failure.
 */
object LockoutPolicy {
    const val FREE_ATTEMPTS = 4
    private val STEPS_MS = longArrayOf(30_000, 60_000, 300_000, 900_000, 3_600_000)

    fun delayForFailures(failures: Int): Long =
        if (failures <= FREE_ATTEMPTS) 0L
        else STEPS_MS[minOf(failures - FREE_ATTEMPTS - 1, STEPS_MS.lastIndex)]

    /** State after one more failed (or about-to-be-checked) attempt. */
    fun registerAttempt(s: FailureState, wall: Long, elapsed: Long, bootId: Int): FailureState {
        val n = s.failures + 1
        return FailureState(n, delayForFailures(n), wall, elapsed, bootId)
    }

    /**
     * Remaining lockout in ms. Takes the LONGER of the monotonic-clock and wall-clock
     * estimates, so changing the system clock cannot shorten a delay.
     * After a reboot the monotonic clock is meaningless, so wall clock is used;
     * if the wall clock went backwards, the full delay is restarted.
     */
    fun remainingMs(s: FailureState, wall: Long, elapsed: Long, bootId: Int): Long {
        if (s.delayMs <= 0L) return 0L
        val wallRemaining =
            if (wall < s.lockedAtWall) s.delayMs else s.lockedAtWall + s.delayMs - wall
        val remaining =
            if (s.bootId == bootId) max(s.lockedAtElapsed + s.delayMs - elapsed, wallRemaining)
            else wallRemaining
        return remaining.coerceAtLeast(0L)
    }
}
