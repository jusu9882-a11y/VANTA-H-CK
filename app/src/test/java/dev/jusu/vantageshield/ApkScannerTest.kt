package dev.jusu.vantageshield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkScannerTest {
    private fun archive(vararg files: Pair<String, String>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            files.forEach { (name, value) ->
                zip.putNextEntry(ZipEntry(name)); zip.write(value.toByteArray()); zip.closeEntry()
            }
        }
        return out.toByteArray()
    }
    @Test fun reportsHttpEndpointIndicator() {
        val r = ApkScanner.scan(archive("classes.dex" to "url=http://example.invalid").inputStream(), "test.apk")
        assertTrue(r.findings.any { it.title == "HTTP URL string found" })
    }
    @Test fun reportsMissingDex() {
        val r = ApkScanner.scan(archive("assets/readme.txt" to "hello").inputStream(), "test.apk")
        assertTrue(r.findings.any { it.title == "No DEX bytecode found" })
    }
    @Test fun malformedDexIsReportedAsUnavailableNotClean() {
        val r = ApkScanner.scan(archive("classes.dex" to "secure endpoint").inputStream(), "test.apk")
        assertTrue(r.findings.any { it.title == "DEX structure unavailable" && it.severity == Severity.LOW })
        assertTrue(r.findings.none { it.severity == Severity.HIGH || it.severity == Severity.CRITICAL })
    }
}
