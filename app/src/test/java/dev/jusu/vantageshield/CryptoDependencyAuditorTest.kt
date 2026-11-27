package dev.jusu.vantageshield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CryptoDependencyAuditorTest {
    @Test fun flagsWeakAlgorithmMarkersAsReviewSignals() {
        val findings = CryptoDependencyAuditor.audit("Cipher AES/ECB/PKCS5Padding and MD5", emptySet())
        val weak = findings.single { it.title == "Weak cryptography indicators" }
        assertEquals(Severity.MEDIUM, weak.severity)
        assertTrue(weak.evidence.contains("AES in ECB mode"))
        assertTrue(weak.evidence.contains("MD5"))
        assertTrue(weak.evidence.contains("actual call paths were not analyzed"))
    }

    @Test fun doesNotTreatOrdinaryWordAsDesAlgorithm() {
        val findings = CryptoDependencyAuditor.audit("DESCRIPTOR_DESCRIPTION", emptySet())
        assertFalse(findings.any { it.title == "Weak cryptography indicators" })
    }

    @Test fun flagsTlsReviewMarkersWithoutClaimingBypass() {
        val findings = CryptoDependencyAuditor.audit("class TrustAllCerts implements X509TrustManager", emptySet())
        val tls = findings.single { it.title == "TLS certificate-validation review indicators" }
        assertEquals(Severity.MEDIUM, tls.severity)
        assertTrue(tls.evidence.contains("does not prove certificate validation is disabled"))
    }

    @Test fun inventoriesNativeLibrariesAndDependencyMetadata() {
        val findings = CryptoDependencyAuditor.audit(
            "",
            setOf("lib/arm64-v8a/libcrypto.so", "META-INF/com.example/library.version")
        )
        assertTrue(findings.any { it.title == "Native libraries included" })
        assertTrue(findings.any { it.title == "Bundled dependency metadata discovered" })
    }

    @Test fun emptyInputHasNoCryptoOrDependencyClaims() {
        assertTrue(CryptoDependencyAuditor.audit("", emptySet()).isEmpty())
    }
}
