package dev.jusu.vantageshield

import java.io.BufferedInputStream
import java.io.InputStream
import java.util.Locale
import java.util.zip.ZipInputStream

/** Passive offline APK archive triage; not a complete manifest or bytecode auditor. */
object ApkScanner {
    private const val MAX_ENTRY_BYTES = 32L * 1024 * 1024
    private const val MAX_TOTAL_BYTES = 128L * 1024 * 1024

    fun scan(input: InputStream, fileName: String): ScanReport {
        val findings = mutableListOf<Finding>()
        val names = mutableSetOf<String>()
        val inspected = StringBuilder()
        var total = 0L
        var entries = 0
        ZipInputStream(BufferedInputStream(input)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                entries++
                names += entry.name
                if (entry.isDirectory) continue
                val capture = entry.name == "AndroidManifest.xml" || entry.name.endsWith(".dex")
                var entryBytes = 0L
                val buffer = ByteArray(8192)
                while (true) {
                    val n = zip.read(buffer)
                    if (n < 0) break
                    entryBytes += n
                    total += n
                    require(entryBytes <= MAX_ENTRY_BYTES && total <= MAX_TOTAL_BYTES) {
                        "APK inspection limit exceeded; archive may be unusually large."
                    }
                    if (capture) inspected.append(String(buffer, 0, n, Charsets.ISO_8859_1))
                }
                zip.closeEntry()
            }
        }
        val lower = inspected.toString().lowercase(Locale.ROOT)
        if ("usescleartexttraffic" in lower || "cleartexttraffic" in lower) findings += Finding(
            "Cleartext traffic configuration indicator", Severity.MEDIUM,
            "Manifest-related bytes contain a cleartext-traffic marker; binary XML decoding is needed to confirm the value.",
            "Decode AndroidManifest.xml and ensure cleartext traffic is disabled except for explicitly justified domains."
        )
        if ("http://" in lower) findings += Finding(
            "HTTP URL string found", Severity.MEDIUM,
            "A DEX or manifest string contains http://; it may be a test endpoint or non-sensitive resource.",
            "Review every occurrence and use HTTPS for network endpoints."
        )
        if (Regex("-----BEGIN (RSA |EC |PRIVATE )?PRIVATE KEY-----", RegexOption.IGNORE_CASE).containsMatchIn(inspected)) findings += Finding(
            "Private-key marker found", Severity.HIGH,
            "A PEM private-key marker appears in inspected strings.",
            "Treat embedded private keys as compromised, rotate them, and keep secrets out of distributed APKs."
        )
        if (Regex("(api[_-]?key|secret|password)\\s*[:=]\\s*[\"'][^\"']{8,}", RegexOption.IGNORE_CASE).containsMatchIn(inspected)) findings += Finding(
            "Possible hard-coded secret", Severity.HIGH,
            "A string resembles a credential assignment; heuristic false positives are possible.",
            "Review locally, revoke exposed credentials, and never ship reusable secrets in an APK."
        )
        if (names.none { it.startsWith("classes") && it.endsWith(".dex") }) findings += Finding(
            "No DEX bytecode found", Severity.LOW, "No classes*.dex archive entry was found.",
            "Confirm that the selected file is a valid Android APK."
        )
        if (findings.isEmpty()) findings += Finding(
            "No high-signal indicators detected", Severity.INFO,
            "The passive heuristics did not identify configured indicators. This does not prove the APK is secure.",
            "Continue with decoded-manifest review, dependency analysis, cryptographic review, and consented dynamic testing."
        )
        return ScanReport(fileName, findings, entries)
    }
}
