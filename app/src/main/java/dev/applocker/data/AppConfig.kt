package dev.applocker.data

import dev.applocker.crypto.FailureState
import dev.applocker.crypto.StoredCredential

enum class RelockPolicy { IMMEDIATE, AFTER_MINUTES, SCREEN_OFF }

class AppLockEntry(
    val packageName: String,
    val credential: StoredCredential,
    val relock: RelockPolicy = RelockPolicy.SCREEN_OFF,
    val relockMinutes: Int = 0,
    val failure: FailureState = FailureState()
) {
    fun copy(failure: FailureState = this.failure) =
        AppLockEntry(packageName, credential, relock, relockMinutes, failure)
}

class AppConfig(
    val version: Int = 1,
    val globalFailure: FailureState = FailureState(),
    val apps: Map<String, AppLockEntry> = emptyMap()
)
