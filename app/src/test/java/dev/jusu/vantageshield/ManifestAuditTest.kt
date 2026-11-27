package dev.jusu.vantageshield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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

    @Test fun malformedBinaryXmlIsRejectedSafely() {
        assertNull(BinaryManifestReader.read(byteArrayOf(3, 0, 8, 0, 1, 0, 0, 0)))
    }
}
