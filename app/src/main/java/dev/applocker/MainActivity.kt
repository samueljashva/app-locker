package dev.applocker

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

/** Placeholder. Real screens arrive in Step 4. */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "App Locker - Step 1 (crypto layer only)"
            setPadding(48, 96, 48, 48)
        })
    }
}
