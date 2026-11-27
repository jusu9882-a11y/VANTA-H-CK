package dev.jusu.vantageshield

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OsvClientTest {
    @Test fun parsesAdvisoryIdentityAliasesAffectedEvidenceAndHttpsReferences() {
        val record = JSONObject(
            """{
              "id":"GHSA-abcd-1234-efgh",
              "summary":"Example vulnerable package",
              "modified":"2026-11-01T00:00:00Z",
              "aliases":["CVE-2026-12345"],
              "references":[
                {"type":"WEB","url":"https://osv.dev/vulnerability/GHSA-abcd-1234-efgh"},
                {"type":"WEB","url":"http://unsafe.example/test"}
              ],
              "affected":[{
                "package":{"name":"okhttp","ecosystem":"Maven"},
                "versions":["4.0.0","4.1.0"],
                "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.2.0"}]}]
              }]
            }"""
        )
        val parsed = OsvClient.parseAdvisory(record, "fallback")!!
        assertEquals("GHSA-abcd-1234-efgh", parsed.id)
        assertEquals(listOf("CVE-2026-12345"), parsed.aliases)
        assertEquals(1, parsed.references.size)
        assertTrue(parsed.affected.single().contains("okhttp"))
        assertTrue(parsed.affected.single().contains("4.2.0").not())
        assertTrue(parsed.affected.single().contains("ECOSYSTEM"))
    }

    @Test fun withdrawnAdvisoriesAreExcluded() {
        val record = JSONObject("""{"id":"OSV-TEST","withdrawn":"2026-10-01T00:00:00Z"}""")
        assertNull(OsvClient.parseAdvisory(record, "fallback"))
    }

    @Test fun missingOptionalFieldsRemainSafeAndExplicit() {
        val parsed = OsvClient.parseAdvisory(JSONObject("""{"id":"OSV-EMPTY"}""), "fallback")!!
        assertEquals("OSV-EMPTY", parsed.id)
        assertEquals("No summary supplied by OSV.", parsed.summary)
        assertTrue(parsed.aliases.isEmpty())
        assertTrue(parsed.references.isEmpty())
        assertTrue(parsed.affected.isEmpty())
        assertFalse(parsed.modified != null)
    }
}
