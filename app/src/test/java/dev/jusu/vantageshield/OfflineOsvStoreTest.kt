package dev.jusu.vantageshield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files
import java.time.Instant

class OfflineOsvStoreTest {
    private val dependency = DependencyCoordinate(
        groupId = "com.example",
        artifactId = "demo",
        version = "1.2.3",
        metadataPath = "META-INF/maven/com.example/demo/pom.properties"
    )
    private val record = """{"id":"OSV-TEST-1","summary":"Test advisory","modified":"2026-11-01T00:00:00Z","references":[{"url":"https://osv.dev/vulnerability/OSV-TEST-1"}]}"""

    @Test fun cachesAndMatchesPreviouslyCheckedExactVersionOffline() {
        val directory = Files.createTempDirectory("vantage-osv-cache").toFile()
        try {
            OfflineOsvStore.merge(directory, OsvCheckResult(
                checkedAt = "2026-11-27T12:00:00Z",
                packagesChecked = 1,
                advisories = emptyList(),
                truncated = false,
                packageMatches = mapOf(dependency.purl to listOf("OSV-TEST-1")),
                rawAdvisories = mapOf("OSV-TEST-1" to record)
            ))
            val result = OfflineOsvStore.check(directory, listOf(dependency), Instant.parse("2026-11-27T13:00:00Z"))
            assertTrue(result.complete)
            assertFalse(result.stale)
            assertEquals(1, result.packagesChecked)
            assertEquals("OSV-TEST-1", result.advisories.single().id)
            assertEquals(listOf(dependency.purl), result.advisories.single().matchedComponents)
            assertEquals(64, result.cacheDigest.length)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test fun reportsUnknownWhenExactPackageVersionWasNeverCached() {
        val directory = Files.createTempDirectory("vantage-osv-empty").toFile()
        try {
            OfflineOsvStore.merge(directory, OsvCheckResult(
                checkedAt = "2026-11-27T12:00:00Z",
                packagesChecked = 1,
                advisories = emptyList(),
                truncated = false,
                packageMatches = mapOf(dependency.purl to emptyList()),
                rawAdvisories = emptyMap()
            ))
            val other = dependency.copy(version = "9.9.9")
            val result = OfflineOsvStore.check(directory, listOf(other))
            assertFalse(result.complete)
            assertEquals(listOf(other.purl), result.missingPackages)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test fun rejectsCacheWhosePayloadDigestDoesNotMatch() {
        val directory = Files.createTempDirectory("vantage-osv-tamper").toFile()
        try {
            OfflineOsvStore.merge(directory, OsvCheckResult(
                checkedAt = "2026-11-27T12:00:00Z",
                packagesChecked = 1,
                advisories = emptyList(),
                truncated = false,
                packageMatches = mapOf(dependency.purl to emptyList()),
                rawAdvisories = emptyMap()
            ))
            val cache = directory.resolve("osv-maven-cache.json")
            cache.writeText(cache.readText().replace("OSV.dev API", "Altered source"))
            val error = runCatching { OfflineOsvStore.check(directory, listOf(dependency)) }.exceptionOrNull()
            assertTrue(error?.message?.contains("integrity check failed") == true)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test fun marksCacheOlderThanThirtyDaysAsStale() {
        val directory = Files.createTempDirectory("vantage-osv-stale").toFile()
        try {
            OfflineOsvStore.merge(directory, OsvCheckResult(
                checkedAt = "2026-01-01T00:00:00Z",
                packagesChecked = 1,
                advisories = emptyList(),
                truncated = false,
                packageMatches = mapOf(dependency.purl to emptyList()),
                rawAdvisories = emptyMap()
            ))
            val result = OfflineOsvStore.check(directory, listOf(dependency), Instant.parse("2026-03-01T00:00:00Z"))
            assertTrue(result.stale)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test fun truncatedOnlineResultsDoNotCreateCompleteOfflineCoverage() {
        val directory = Files.createTempDirectory("vantage-osv-truncated").toFile()
        try {
            OfflineOsvStore.merge(directory, OsvCheckResult(
                checkedAt = "2026-11-27T12:00:00Z",
                packagesChecked = 1,
                advisories = emptyList(),
                truncated = true,
                packageMatches = mapOf(dependency.purl to emptyList()),
                rawAdvisories = emptyMap()
            ))
            val result = OfflineOsvStore.check(directory, listOf(dependency))
            assertFalse(result.complete)
        } finally {
            directory.deleteRecursively()
        }
    }
}
