package dev.jusu.vantageshield

/**
 * String-level triage only. These markers can be dead code, library strings, or documentation;
 * they do not establish that an algorithm or TLS override is actually used at runtime.
 */
object CryptoDependencyAuditor {
    private val weakAlgorithms = listOf(
        "AES/ECB" to "AES in ECB mode",
        "DES" to "DES",
        "DESede" to "3DES",
        "RC4" to "RC4",
        "MD5" to "MD5",
        "SHA1" to "SHA-1",
        "SHA-1" to "SHA-1"
    )
    private val trustMarkers = listOf(
        "TrustAllCerts", "ALLOW_ALL_HOSTNAME_VERIFIER", "HostnameVerifier",
        "X509TrustManager", "checkServerTrusted", "setDefaultHostnameVerifier",
        "setHostnameVerifier"
    )

    fun audit(strings: String, entries: Set<String>): List<Finding> = buildList {
        val normalized = strings.uppercase()
        val weak = weakAlgorithms.filter { marker ->
            val token = marker.first.uppercase()
            if (token == "AES/ECB") normalized.contains(token)
            else Regex("(?<![A-Z0-9])" + Regex.escape(token) + "(?![A-Z0-9])").containsMatchIn(normalized)
        }
        if (weak.isNotEmpty()) add(Finding(
            "Weak cryptography indicators", Severity.MEDIUM,
            "Inspected DEX/native strings contain marker(s): " + weak.joinToString { it.second } +
                ". Strings may belong to unused code or bundled libraries; actual call paths were not analyzed.",
            "Trace each marker to reachable code. Prefer modern authenticated encryption such as AES-GCM or ChaCha20-Poly1305, and SHA-256 or stronger for hashing where appropriate. Do not use hashes as password storage."
        ))

        val tls = trustMarkers.filter { strings.contains(it, ignoreCase = true) }
        if (tls.isNotEmpty()) add(Finding(
            "TLS certificate-validation review indicators", Severity.MEDIUM,
            "Inspected strings contain TLS trust/hostname marker(s): " + tls.joinToString() +
                ". Presence alone does not prove certificate validation is disabled.",
            "Inspect implementations and call sites. Never accept all certificates or hostnames in production; retain normal platform certificate and hostname validation."
        ))

        val metadata = entries.filter {
            it.startsWith("META-INF/") &&
                (it.endsWith(".version", true) || it.endsWith("pom.properties", true) || it.endsWith("pom.xml", true))
        }
        if (metadata.isNotEmpty()) add(Finding(
            "Bundled dependency metadata discovered", Severity.INFO,
            "Found " + metadata.size + " dependency metadata file(s): " + metadata.take(12).joinToString() +
                if (metadata.size > 12) " and more." else ".",
            "Use these metadata files as leads for a complete SBOM and vulnerability review. Their absence does not mean the APK has no third-party dependencies."
        ))

        val native = entries.filter { it.startsWith("lib/") && it.endsWith(".so", true) }
        if (native.isNotEmpty()) add(Finding(
            "Native libraries included", Severity.INFO,
            "APK contains " + native.size + " native shared library file(s): " + native.take(12).joinToString() +
                if (native.size > 12) " and more." else ".",
            "Inventory each native library's origin and version, then review its update status and native security properties."
        ))
    }
}
