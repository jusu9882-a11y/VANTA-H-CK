package dev.jusu.vantageshield

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.time.Instant

data class OsvAdvisory(
    val id: String,
    val summary: String,
    val modified: String?,
    val aliases: List<String>,
    val references: List<String>,
    val affected: List<String>,
    val severity: String?
)

data class OsvCheckResult(
    val checkedAt: String,
    val packagesChecked: Int,
    val advisories: List<OsvAdvisory>,
    val truncated: Boolean
)

/**
 * Explicit, online OSV lookup. It only queries exact Maven coordinates recovered from
 * embedded pom.properties. Network errors throw and must be presented as UNKNOWN, never clean.
 */
object OsvClient {
    private const val QUERY_URL = "https://api.osv.dev/v1/querybatch"
    private const val VULN_URL = "https://api.osv.dev/v1/vulns/"
    private const val MAX_PACKAGES = 100
    private const val MAX_ADVISORIES = 100
    private const val MAX_RESPONSE_BYTES = 1024 * 1024
    private const val TIMEOUT_MS = 12_000

    fun check(dependencies: List<DependencyCoordinate>): OsvCheckResult {
        val unique = dependencies.distinctBy { it.purl }.sortedBy { it.purl }
        require(unique.isNotEmpty()) { "No exact Maven coordinates are available for OSV lookup." }
        val selected = unique.take(MAX_PACKAGES)
        val queries = JSONArray()
        selected.forEach { dep ->
            val packageUrl = "pkg:maven/${dep.groupId}/${dep.artifactId}"
            queries.put(JSONObject()
                .put("package", JSONObject().put("purl", packageUrl))
                .put("version", dep.version))
        }

        val batch = request(QUERY_URL, "POST", JSONObject().put("queries", queries).toString())
        val results = batch.optJSONArray("results")
            ?: error("OSV response did not contain a results array.")
        require(results.length() == selected.size) { "OSV returned an unexpected result count." }

        val ids = linkedSetOf<String>()
        for (i in 0 until results.length()) {
            val vulns = results.optJSONObject(i)?.optJSONArray("vulns") ?: continue
            for (j in 0 until vulns.length()) {
                val id = vulns.optJSONObject(j)?.optString("id").orEmpty()
                if (id.matches(Regex("[A-Za-z0-9._-]{1,128}"))) ids += id
            }
        }

        val truncated = unique.size > MAX_PACKAGES || ids.size > MAX_ADVISORIES
        val advisories = ids.take(MAX_ADVISORIES).mapNotNull { id ->
            parseAdvisory(request(VULN_URL + id, "GET", null), id)
        }.distinctBy { it.id }.sortedBy { it.id }

        return OsvCheckResult(Instant.now().toString(), selected.size, advisories, truncated)
    }


    internal fun parseAdvisory(record: JSONObject, fallbackId: String): OsvAdvisory? {
        if (record.has("withdrawn") && !record.isNull("withdrawn")) return null
        val affected = record.optJSONArray("affected")
        val affectedSummary = if (affected == null) emptyList() else
            (0 until affected.length()).mapNotNull { index ->
                val item = affected.optJSONObject(index) ?: return@mapNotNull null
                val pkg = item.optJSONObject("package")
                val name = pkg?.optString("name").orEmpty()
                val ecosystem = pkg?.optString("ecosystem").orEmpty()
                val versionList = item.optJSONArray("versions")
                val versions = if (versionList == null) emptyList() else
                    (0 until versionList.length()).map { versionList.optString(it) }.filter(String::isNotBlank).take(12)
                val rangeList = item.optJSONArray("ranges")
                val rangeTypes = if (rangeList == null) emptyList() else
                    (0 until rangeList.length()).mapNotNull { rangeList.optJSONObject(it)?.optString("type") }.distinct()
                val identity = listOf(name, ecosystem).filter(String::isNotBlank).joinToString(" • ")
                if (identity.isBlank()) null else identity + buildString {
                    if (versions.isNotEmpty()) append(" • listed versions: " + versions.joinToString())
                    if (rangeTypes.isNotEmpty()) append(" • ranges: " + rangeTypes.joinToString())
                }
            }.take(20)
        val severityValues = mutableListOf<String>()
        val severityArray = record.optJSONArray("severity")
        if (severityArray != null) for (i in 0 until severityArray.length()) {
            severityArray.optJSONObject(i)?.optString("score")?.takeIf(String::isNotBlank)?.let(severityValues::add)
        }
        val aliases = record.optJSONArray("aliases").toStringList()
        val references = record.optJSONArray("references").toReferenceUrls()
        return OsvAdvisory(
            id = record.optString("id", fallbackId),
            summary = record.optString("summary").ifBlank { "No summary supplied by OSV." },
            modified = record.optString("modified").takeIf { it.isNotBlank() },
            aliases = aliases,
            references = references,
            affected = affectedSummary,
            severity = severityValues.firstOrNull()
        )
    }

    private fun request(endpoint: String, method: String, body: String?): JSONObject {
        val connection = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = TIMEOUT_MS
            readTimeout = TIMEOUT_MS
            setRequestProperty("Accept", "application/json")
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
        }
        try {
            if (body != null) {
                connection.outputStream.use { it.write(body.toByteArray(StandardCharsets.UTF_8)) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val payload = stream?.use { input ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= MAX_RESPONSE_BYTES) { "OSV response exceeded the 1 MiB safety limit." }
                    output.write(buffer, 0, count)
                }
                output.toString(StandardCharsets.UTF_8.name())
            }.orEmpty()
            if (status !in 200..299) error("OSV returned HTTP $status.")
            return JSONObject(payload)
        } finally {
            connection.disconnect()
        }
    }

    private fun JSONArray?.toStringList(): List<String> {
        if (this == null) return emptyList()
        return (0 until length()).mapNotNull { optString(it).takeIf(String::isNotBlank) }
    }

    private fun JSONArray?.toReferenceUrls(): List<String> {
        if (this == null) return emptyList()
        return (0 until length()).mapNotNull { optJSONObject(it)?.optString("url") }
            .filter { it.startsWith("https://") }.distinct().take(20)
    }
}
