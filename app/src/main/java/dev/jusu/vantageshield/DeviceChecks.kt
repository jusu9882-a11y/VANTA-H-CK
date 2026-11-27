package dev.jusu.vantageshield

import android.bluetooth.BluetoothManager
import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings

data class DeviceCheck(val name: String, val status: String, val detail: String)
object DeviceChecks {
    fun run(context: Context): List<DeviceCheck> {
        val checks = mutableListOf<DeviceCheck>()
        checks += DeviceCheck("Android version", "INFO", "API ${Build.VERSION.SDK_INT} (${Build.VERSION.RELEASE})")
        val dev = runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1 }.getOrNull()
        checks += DeviceCheck("Developer options", when (dev) { true -> "REVIEW"; false -> "OK"; null -> "UNKNOWN" },
            when (dev) { true -> "Enabled."; false -> "Disabled."; null -> "Could not read this setting." })
        val bt = runCatching { (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter?.isEnabled }.getOrNull()
        checks += DeviceCheck("Bluetooth radio", when (bt) { true -> "INFO"; false -> "OK"; null -> "UNKNOWN" },
            when (bt) { true -> "Enabled; this is not itself a vulnerability."; false -> "Disabled."; null -> "Unavailable or restricted." })
        @Suppress("DEPRECATION")
        val wifi = runCatching { (context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager).isWifiEnabled }.getOrNull()
        checks += DeviceCheck("Wi-Fi radio", when (wifi) { true -> "INFO"; false -> "OK"; null -> "UNKNOWN" },
            when (wifi) { true -> "Enabled; connection security was not tested."; false -> "Disabled."; null -> "Unavailable." })
        return checks
    }
}
