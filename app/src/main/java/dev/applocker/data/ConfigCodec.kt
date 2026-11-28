package dev.applocker.data

import android.util.Base64
import dev.applocker.crypto.CredentialType
import dev.applocker.crypto.FailureState
import dev.applocker.crypto.StoredCredential
import org.json.JSONArray
import org.json.JSONObject

/** AppConfig <-> JSON bytes (platform org.json, no extra dependencies). Encrypted by SecureStore. */
object ConfigCodec {
    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)

    fun encode(c: AppConfig): ByteArray = JSONObject().apply {
        put("v", c.version)
        put("global", failure(c.globalFailure))
        put("apps", JSONArray().apply { c.apps.values.forEach { put(app(it)) } })
    }.toString().toByteArray(Charsets.UTF_8)

    fun decode(bytes: ByteArray): AppConfig {
        val o = JSONObject(String(bytes, Charsets.UTF_8))
        val apps = LinkedHashMap<String, AppLockEntry>()
        val arr = o.getJSONArray("apps")
        for (i in 0 until arr.length()) {
            val e = app(arr.getJSONObject(i))
            apps[e.packageName] = e
        }
        return AppConfig(o.getInt("v"), failure(o.getJSONObject("global")), apps)
    }

    private fun failure(f: FailureState) = JSONObject()
        .put("n", f.failures).put("d", f.delayMs)
        .put("w", f.lockedAtWall).put("e", f.lockedAtElapsed).put("b", f.bootId)

    private fun failure(o: JSONObject) = FailureState(
        o.getInt("n"), o.getLong("d"), o.getLong("w"), o.getLong("e"), o.getInt("b")
    )

    private fun app(e: AppLockEntry) = JSONObject()
        .put("pkg", e.packageName)
        .put("type", e.credential.type.name)
        .put("salt", b64(e.credential.salt))
        .put("it", e.credential.iterations)
        .put("tag", b64(e.credential.tag))
        .put("relock", e.relock.name)
        .put("mins", e.relockMinutes)
        .put("fail", failure(e.failure))

    private fun app(o: JSONObject) = AppLockEntry(
        packageName = o.getString("pkg"),
        credential = StoredCredential(
            CredentialType.valueOf(o.getString("type")),
            unb64(o.getString("salt")), o.getInt("it"), unb64(o.getString("tag"))
        ),
        relock = RelockPolicy.valueOf(o.getString("relock")),
        relockMinutes = o.getInt("mins"),
        failure = failure(o.getJSONObject("fail"))
    )
}
