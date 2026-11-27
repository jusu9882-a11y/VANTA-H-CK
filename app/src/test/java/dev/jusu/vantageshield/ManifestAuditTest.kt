package dev.jusu.vantageshield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull\nimport java.util.Random\nimport java.io.ByteArrayOutputStream\nimport java.nio.ByteBuffer\nimport java.nio.ByteOrder
import org.junit.Assert.assertTrue
import org.junit.Test

class ManifestAuditTest {
    @Test fun detectsDebuggableCleartextAndBackup() {
        val findings = ManifestAuditor.audit(ManifestFacts(
            debuggable = true,
            allowBackup = true,
            usesCleartextTraffic = true
        ))
        assertTrue(findings.any { it.title == "Debuggable application enabled" && it.severity == Severity.HIGH })
        assertTrue(findings.any { it.title == "Cleartext traffic explicitly enabled" && it.severity == Severity.HIGH })
        assertTrue(findings.any { it.title == "Application backup is enabled" && it.severity == Severity.MEDIUM })
    }

    @Test fun flagsUnprotectedExportedComponentButDoesNotCallItExploitable() {
        val findings = ManifestAuditor.audit(ManifestFacts(components = listOf(
            ManifestComponent("service", ".SyncService", true, null, true)
        )))
        val finding = findings.single { it.title == "Exported components without component permission" }
        assertEquals(Severity.MEDIUM, finding.severity)
        assertTrue(finding.evidence.contains("not proof of exploitability"))
    }

    @Test fun explicitPermissionAvoidsUnprotectedExportFinding() {
        val findings = ManifestAuditor.audit(ManifestFacts(components = listOf(
            ManifestComponent("receiver", ".ProtectedReceiver", true, "dev.example.SIGNATURE", true)
        )))
        assertFalse(findings.any { it.title == "Exported components without component permission" })
    }

    @Test fun oldTargetSdkIsFlagged() {
        val findings = ManifestAuditor.audit(ManifestFacts(targetSdk = 28))
        assertTrue(findings.any { it.title == "Outdated target SDK" })
    }

    @Test fun readsMinimalCompiledManifestAndPackageName() {
        val bytes = minimalBinaryManifest()
        val facts = BinaryManifestReader.read(bytes)
        assertTrue(facts != null)
        assertEquals("com.example.app", facts?.packageName)
    }

    private fun minimalBinaryManifest(): ByteArray {
        val strings = listOf("manifest", "package", "com.example.app")
        val pool = ByteArrayOutputStream()
        val encoded = ByteArrayOutputStream()
        val offsets = mutableListOf<Int>()
        strings.forEach { value ->
            offsets += encoded.size()
            val raw = value.toByteArray(Charsets.UTF_8)
            encoded.write(raw.size)
            encoded.write(raw.size)
            encoded.write(raw)
            encoded.write(0)
        }
        val poolHeaderSize = 28
        val stringsStart = poolHeaderSize + strings.size * 4
        val poolSize = stringsStart + encoded.size()
        val poolBuffer = ByteBuffer.allocate(poolSize).order(ByteOrder.LITTLE_ENDIAN)
        poolBuffer.putShort(0x0001.toShort()).putShort(poolHeaderSize.toShort()).putInt(poolSize)
        poolBuffer.putInt(strings.size).putInt(0).putInt(0x100).putInt(stringsStart).putInt(0)
        offsets.forEach { poolBuffer.putInt(it) }
        poolBuffer.put(encoded.toByteArray())

        val start = ByteBuffer.allocate(56).order(ByteOrder.LITTLE_ENDIAN)
        start.putShort(0x0102.toShort()).putShort(16).putInt(56)
        start.putInt(1).putInt(-1)
        start.putInt(-1).putInt(0)
        start.putShort(20).putShort(20).putShort(1).putShort(0).putShort(0).putShort(0)
        start.putInt(-1).putInt(1).putInt(2)
        start.putShort(8).put(0).put(3).putInt(2)

        val end = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
        end.putShort(0x0103.toShort()).putShort(16).putInt(24)
        end.putInt(1).putInt(-1).putInt(-1).putInt(0)

        val total = 8 + poolSize + start.capacity() + end.capacity()
        val document = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
        document.putShort(0x0003.toShort()).putShort(8).putInt(total)
        document.put(poolBuffer.array()).put(start.array()).put(end.array())
        return document.array()
    }

    @Test fun malformedBinaryXmlIsRejectedSafely() {
        assertNull(BinaryManifestReader.read(byteArrayOf(3, 0, 8, 0, 1, 0, 0, 0)))
    }
}
