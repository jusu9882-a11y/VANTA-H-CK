package dev.jusu.vantageshield

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class ManifestComponent(val type: String, val name: String, val exported: Boolean?, val permission: String?, val hasIntentFilter: Boolean)
data class ManifestFacts(
    val packageName: String? = null, val minSdk: Int? = null, val targetSdk: Int? = null,
    val debuggable: Boolean? = null, val allowBackup: Boolean? = null, val usesCleartextTraffic: Boolean? = null,
    val permissions: List<String> = emptyList(), val components: List<ManifestComponent> = emptyList()
)

/** Focused reader for Android's compiled binary XML manifest format. */
object BinaryManifestReader {
    private const val STRING_POOL = 0x0001
    private const val START_ELEMENT = 0x0102
    private const val END_ELEMENT = 0x0103
    private const val NO_INDEX = -1

    fun read(bytes: ByteArray): ManifestFacts? {
        if ( bytes.size < 8) return null
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        if (u16(b, 0) != 0x0003) return null
        var offset = u16(b, 2).coerceAtLeast(8)
        var strings = emptyList<String>()
        var pkg: String? = null
        var min: Int? = null
        var target: Int? = null
        var debug: Boolean? = null
        var backup: Boolean? = null
        var cleartext: Boolean? = null
        val permissions = linkedSetOf<String>()
        val components = mutableListOf<ManifestComponent>()
        val stack = mutableListOf<MutableComponent>()

        while (offset + 8 <= bytes.size) {
            val type = u16(b, offset)
            val header = u16(b, offset + 2)
            val size = b.getInt(offset + 4)
            if (header < 8 || size < header || size <= 0 || offset.toLong() + size > bytes.size) return null
            when (type) {
                STRING_POOL -> strings = stringPool(b, offset, header, size)
                START_ELEMENT -> {
                    if (size < 36 || strings.isEmpty()) return null
                    val tag = strings.getOrNull(b.getInt(offset + 20)) ?: ""
                    val attrStart = u16(b, offset + 24)
                    val attrSize = u16(b, offset + 26)
                    val attrCount = u16(b, offset + 28)
                    if (attrSize < 20) return null
                    val attrs = mutableMapOf<String, String>()
                    val base = offset + 16 + attrStart
                    for (i in 0 until attrCount) {
                        val at = base + i * attrSize
                        if (at + 20 > offset + size) return null
                        val name = strings.getOrNull(b.getInt(at + 4)) ?: continue
                        val raw = b.getInt(at + 8)
                        val valueType = b.get(at + 15).toInt() and 255
                        val data = b.getInt(at + 16)
                        val value = when {
                            raw != NO_INDEX -> strings.getOrNull(raw)
                            valueType == 3 -> strings.getOrNull(data)
                            valueType == 0x12 -> (data != 0).toString()
                            valueType == 0x10 || valueType == 0x11 -> data.toString()
                            else -> null
                        }
                        if (value != null) attrs[name] = value
                    }
                    when (tag) {
                        "manifest" -> pkg = attrs["package"]
                        "uses-sdk" -> { min = attrs["minSdkVersion"]?.toIntOrNull(); target = attrs["targetSdkVersion"]?.toIntOrNull() }
                        "uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m" -> attrs["name"]?.let { permissions += it }
                        "application" -> {
                            debug = attrs["debuggable"]?.toBooleanStrictOrNull()
                            backup = attrs["allowBackup"]?.toBooleanStrictOrNull()
                            cleartext = attrs["usesCleartextTraffic"]?.toBooleanStrictOrNull()
                        }
                        "activity", "activity-alias", "service", "receiver", "provider" ->
                            stack += MutableComponent(tag, attrs["name"] ?: "(unnamed)", attrs["exported"]?.toBooleanStrictOrNull(), attrs["permission"] ?: "")
                        "intent-filter" -> stack.lastOrNull()?.intentFilter = true
                    }
                }
                END_ELEMENT -> {
                    if (size >= 24) {
                        val tag = strings.getOrNull(b.getInt(offset + 20))
                        if (tag in COMPONENT_TAGS) stack.removeLastOrNull()?.let { components += it.result() }
                    }
                }
            }
            offset += size
        }
        return ManifestFacts(pkg, min, target, debug, backup, cleartext, permissions.toList(), components)
    }

    private data class MutableComponent(val type: String, val name: String, val exported: Boolean?, val permission: String, var intentFilter: Boolean = false) {
        fun result() = ManifestComponent(type, name, exported, permission.ifBlank { null }, intentFilter)
    }

    private fun stringPool(b: ByteBuffer, off: Int, header: Int, size: Int): List<String> {
        if (header < 28) return emptyList()
        val count = b.getInt(off + 8)
        val flags = b.getInt(off + 16)
        val start = b.getInt(off + 20)
        if (count !in 0..100000 || start < header || start >= size) return emptyList()
        return (0 until count).map { i ->
            val pos = off + header + i * 4
            if (pos + 4 > off + size) return emptyList()
            val str = off + start + b.getInt(pos)
            if (str < off || str >= off + size) return emptyList()
            if ((flags and 0x100) != 0) utf8(b, str, off + size) else utf16(b, str, off + size)
        }
    }

    private fun utf8(b: ByteBuffer, start: Int, limit: Int): String {
        var p = start
        p = length8(b, p).second
        val (length, next) = length8(b, p); p = next
        if (length < 0 || p + length > limit) return ""
        return ByteArray(length) { b.get(p + it) }.toString(Charsets.UTF_8)
    }
    private fun utf16(b: ByteBuffer, start: Int, limit: Int): String {
        var p = start
        if (p + 2 > limit) return ""
        var n = u16(b, p); p += 2
        if ((n and 0x8000) != 0) { if (p + 2 > limit) return ""; n = ((n and 0x7fff) shl 16) or u16(b, p); p += 2 }
        if (n < 0 || p + n * 2 > limit) return ""
        return String(CharArray(n) { b.getShort(p + it * 2).toInt().toChar() })
    }
    private fun length8(b: ByteBuffer, p: Int): Pair<Int, Int> {
        val x = b.get(p).toInt() and 255
        return if (x and 0x80 != 0) (((x and 0x7f) shl 8) or (b.get(p + 1).toInt() and 255)) to p + 2 else x to p + 1
    }
    private fun u16(b: ByteBuffer, p: Int) = b.getShort(p).toInt() and 65535
    private val COMPONENT_TAGS = setOf("activity", "activity-alias", "service", "receiver", "provider")
}

object ManifestAuditor {
    fun audit(f: ManifestFacts): List<Finding> = buildList {
        if (f.debuggable == true) add(Finding("Debuggable application enabled", Severity.HIGH,
            "Decoded manifest sets android:debuggable=true.", "Disable debuggable in release builds and verify the release variant."))
        if (f.usesCleartextTraffic == true) add(Finding("Cleartext traffic explicitly enabled", Severity.HIGH,
            "Decoded manifest sets android:usesCleartextTraffic=true.", "Disable cleartext traffic or narrowly scope justified exceptions."))
        if (f.allowBackup == true) add(Finding("Application backup is enabled", Severity.MEDIUM,
            "Decoded manifest sets android:allowBackup=true.", "Review backup rules and exclude credentials, tokens, private keys, and sensitive data."))
        if (f.targetSdk != null && f.targetSdk < 29) add(Finding("Outdated target SDK", Severity.MEDIUM,
            "Decoded targetSdkVersion is " + f.targetSdk + ".", "Update to a currently supported Android API and regression-test behavior."))
        val exposed = f.components.filter { it.exported == true && it.permission.isNullOrBlank() }
        if (exposed.isNotEmpty()) add(Finding("Exported components without component permission", Severity.MEDIUM,
            "Manifest exposes " + exposed.size + " component(s) with exported=true and no component-level permission: " +
                exposed.joinToString { it.type + " " + it.name } + ". Export alone is not proof of exploitability.",
            "Review each component's intent filters and callable operations; require signature-level permissions or set exported=false where external access is unnecessary."))
        if (f.permissions.isNotEmpty()) add(Finding("Manifest permission inventory", Severity.INFO,
            "Decoded manifest declares " + f.permissions.size + " permission(s): " + f.permissions.joinToString() + ".",
            "Verify each permission is required, requested at runtime where applicable, and disclosed to users."))
        if (isEmpty()) add(Finding("No manifest risks detected by current rules", Severity.INFO,
            "Decoded manifest did not match current audit rules. This is not a complete security assessment.",
            "Continue with dependency, DEX, native-library, cryptographic, and authorized runtime analysis."))
    }
}
