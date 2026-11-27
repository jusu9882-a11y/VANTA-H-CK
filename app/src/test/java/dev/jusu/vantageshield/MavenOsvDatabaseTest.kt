package dev.jusu.vantageshield

import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class MavenOsvDatabaseTest {
    @Test fun evaluatesMavenEcosystemRangesWithExclusiveFixedBoundary() {
        val events = JSONArray()
            .put(org.json.JSONObject().put("introduced", "0"))
            .put(org.json.JSONObject().put("fixed", "2.0.0"))
        assertTrue(MavenOsvDatabase.rangeAffects(events, "1.9.9") == true)
        assertFalse(MavenOsvDatabase.rangeAffects(events, "2.0.0") == true)
    }

    @Test fun evaluatesLastAffectedAsInclusive() {
        val events = JSONArray()
            .put(org.json.JSONObject().put("introduced", "1.0.0"))
            .put(org.json.JSONObject().put("last_affected", "1.5.0"))
        assertTrue(MavenOsvDatabase.rangeAffects(events, "1.5.0") == true)
        assertFalse(MavenOsvDatabase.rangeAffects(events, "1.5.1") == true)
    }

    @Test fun rejectsMalformedOrEmptyRangeEventsAsUnknown() {
        assertNull(MavenOsvDatabase.rangeAffects(JSONArray(), "1.0"))
        assertNull(MavenOsvDatabase.rangeAffects(
            JSONArray().put(org.json.JSONObject().put("fixed", "not a valid range?")),
            "1.0"
        ))
    }

    @Test fun validatesAWellFormedMavenArchiveAndCountsRecords() {
        val file = Files.createTempFile("osv-maven", ".zip").toFile()
        try {
            writeZip(file, "GHSA-test-1234.json", """{"id":"GHSA-test-1234","affected":[]}""")
            assertEquals(1, MavenOsvDatabase.validateArchive(file))
        } finally { file.delete() }
    }

    @Test fun rejectsArchivePathTraversalAndMismatchedRecordIdentity() {
        val traversal = Files.createTempFile("osv-maven-path", ".zip").toFile()
        val mismatch = Files.createTempFile("osv-maven-id", ".zip").toFile()
        try {
            writeZip(traversal, "../GHSA-test.json", """{"id":"GHSA-test"}""")
            assertTrue(runCatching { MavenOsvDatabase.validateArchive(traversal) }.isFailure)
            writeZip(mismatch, "GHSA-one.json", """{"id":"GHSA-two"}""")
            assertTrue(runCatching { MavenOsvDatabase.validateArchive(mismatch) }.isFailure)
        } finally {
            traversal.delete()
            mismatch.delete()
        }
    }

    private fun writeZip(file: File, name: String, json: String) {
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry(name))
            zip.write(json.toByteArray(Charsets.UTF_8))
            zip.closeEntry()
        }
    }
}
