package dev.jusu.vantageshield

import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant

data class OfflineOsvCheck(
    val checkedAt: String,
    val packagesChecked: Int,
    val missingPackages: List<String>,
    val advisories: List<OsvAdvisory>,
    val stale: Boolean,
    val cacheDigest: String
) {
    val complete: Boolean get() = missingPackages.isEmpty()
}

/**
 * Persistent, exact-version cache of OSV records previously returned for this app's
 * queried Maven coordinates. This is NOT the full Maven OSV database.
 *
 * The SHA-256 envelope detects accidental corruption. It is not a signature and
 * does not authenticate OSV as the publisher; source authenticity relies on HTTPS
 * during the online lookup.
 */
object OfflineOsvStore {
    private const val FILE_NAME = "osv-maven-cache.json"
    private const val SCHEMA_VERSION = 1
    private const val MAX_CACHE_BYTES = 16 * 1024 * 1024
    private val STALE_AFTER = Duration.ofDays(30)

    fun merge(directory: File, result: OsvCheckResult) {
        require(result.packageMatches.isNotEmpty()) { "OSV returned no package coverage to cache." }
        require(result.packageMatches.size == result.packagesChecked) {
            "OSV package coverage is incomplete; refusing to update the offline cache."
        }
        val target = File(directory, FILE_NAME)
        val payload = if (target.exists()) readVerifiedPayload(target) else emptyPayload()
        val packages = payload.optJSONObject("packages") ?: JSONObject()
        val records = payload.optJSONObject("records") ?: JSONObject()

        if (!result.truncated) {
            result.packageMatches.forEach { (purl, ids) ->
                require(purl.matches(Regex("pkg:maven/[A-Za-z0-9_.+!~*'()-]+/[A-Za-z0-9_.+!~*'()-]+@[A-Za-z0-9_.+!~*'()-]+"))) {
                    "Invalid Maven package URL in OSV cache input."
                }
                packages.put(purl, JSONObject()
                    .put("checkedAt", result.checkedAt)
                    .put("advisoryIds", org.json.JSONArray(ids.distinct().sorted())))
            }
        }
        result.rawAdvisories.forEach { (id, raw) ->
            require(id.matches(Regex("[A-Za-z0-9._-]{1,128}")))
            val record = JSONObject(raw)
            require(record.optString("id") == id) { "OSV record ID mismatch in cache input." }
            records.put(id, record.toString())
        }

        val referencedIds = mutableSetOf<String>()
        val packageKeys = packages.keys()
        while (packageKeys.hasNext()) {
            val entry = packages.optJSONObject(packageKeys.next()) ?: continue
            val ids = entry.optJSONArray("advisoryIds") ?: continue
            for (index in 0 until ids.length()) ids.optString(index).takeIf(String::isNotBlank)?.let(referencedIds::add)
        }
        records.keys().asSequence().filterNot(referencedIds::contains).toList().forEach { records.remove(it) }

        payload.put("schemaVersion", SCHEMA_VERSION)
            .put("source", "OSV.dev API over HTTPS")
            .put("updatedAt", result.checkedAt)
            .put("packages", packages)
            .put("records", records)

        val payloadText = payload.toString()
        val envelope = JSONObject()
            .put("payload", payloadText)
            .put("sha256", sha256(payloadText.toByteArray(StandardCharsets.UTF_8)))
            .toString()
        val bytes = envelope.toByteArray(StandardCharsets.UTF_8)
        require(bytes.size <= MAX_CACHE_BYTES) { "Offline advisory cache exceeds the 16 MiB safety limit." }

        if (!directory.exists() && !directory.mkdirs()) error("Unable to create the offline cache directory.")
        val temp = File(directory, "$FILE_NAME.tmp")
        FileOutputStream(temp).use { stream ->
            stream.write(bytes)
            stream.flush()
            stream.fd.sync()
        }
        try {
            Files.move(temp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (_: Exception) {
            Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
    }

    fun check(directory: File, dependencies: List<DependencyCoordinate>, now: Instant = Instant.now()): OfflineOsvCheck {
        val unique = dependencies.distinctBy { it.purl }.sortedBy { it.purl }
        require(unique.isNotEmpty()) { "No exact Maven coordinates are available for offline lookup." }
        val target = File(directory, FILE_NAME)
        require(target.exists()) { "OFFLINE CACHE UNKNOWN: no OSV records have been cached yet. Run an online OSV check first." }
        val payload = readVerifiedPayload(target)
        require(payload.optInt("schemaVersion", -1) == SCHEMA_VERSION) { "OFFLINE CACHE UNKNOWN: unsupported cache schema." }
        require(payload.optString("source") == "OSV.dev API over HTTPS") {
            "OFFLINE CACHE UNKNOWN: unrecognized advisory data source."
        }
        val packages = payload.optJSONObject("packages") ?: error("OFFLINE CACHE UNKNOWN: package coverage is missing.")
        val records = payload.optJSONObject("records") ?: error("OFFLINE CACHE UNKNOWN: advisory records are missing.")
        val missing = mutableListOf<String>()
        val matchedIds = linkedMapOf<String, MutableList<String>>()
        val checkTimes = mutableListOf<Instant>()

        unique.forEach { dependency ->
            val entry = packages.optJSONObject(dependency.purl)
            if (entry == null) {
                missing += dependency.purl
            } else {
                val checked = runCatching { Instant.parse(entry.optString("checkedAt")) }.getOrNull()
                val ids = entry.optJSONArray("advisoryIds")
                if (checked == null || ids == null || checked.isAfter(now.plus(Duration.ofHours(24)))) {
                    missing += dependency.purl
                } else {
                    checkTimes += checked
                    for (i in 0 until ids.length()) {
                        val id = ids.optString(i)
                        if (!id.matches(Regex("[A-Za-z0-9._-]{1,128}")) || records.optString(id).isBlank()) {
                            missing += dependency.purl
                            break
                        }
                        matchedIds.getOrPut(id) { mutableListOf() }.add(dependency.purl)
                    }
                }
            }
        }

        if (missing.isNotEmpty()) return OfflineOsvCheck(
            checkedAt = checkTimes.minOrNull()?.toString() ?: payload.optString("updatedAt"),
            packagesChecked = unique.size - missing.size,
            missingPackages = missing,
            advisories = emptyList(),
            stale = true,
            cacheDigest = sha256(target.readBytes())
        )

        val advisories = matchedIds.map { (id, purls) ->
            val raw = records.optString(id)
            require(raw.isNotBlank()) { "OFFLINE CACHE UNKNOWN: cached advisory record $id is missing." }
            val record = JSONObject(raw)
            require(record.optString("id") == id) { "OFFLINE CACHE UNKNOWN: cached advisory identity mismatch." }
            OsvClient.parseAdvisory(record, id, purls.distinct())
        }.filterNotNull().distinctBy { it.id }.sortedBy { it.id }

        val oldest = checkTimes.minOrNull() ?: Instant.EPOCH
        val stale = Duration.between(oldest, now).let { !it.isNegative && it > STALE_AFTER }
        return OfflineOsvCheck(
            checkedAt = oldest.toString(),
            packagesChecked = unique.size,
            missingPackages = emptyList(),
            advisories = advisories,
            stale = stale,
            cacheDigest = sha256(target.readBytes())
        )
    }

    private fun emptyPayload() = JSONObject()
        .put("schemaVersion", SCHEMA_VERSION)
        .put("source", "OSV.dev API over HTTPS")
        .put("updatedAt", JSONObject.NULL)
        .put("packages", JSONObject())
        .put("records", JSONObject())

    private fun readVerifiedPayload(file: File): JSONObject {
        require(file.length() in 1..MAX_CACHE_BYTES.toLong()) { "OFFLINE CACHE UNKNOWN: cache size is invalid." }
        val envelope = JSONObject(file.readText(Charsets.UTF_8))
        val payloadText = envelope.optString("payload")
        val expected = envelope.optString("sha256")
        require(payloadText.isNotBlank() && expected.matches(Regex("[a-f0-9]{64}"))) {
            "OFFLINE CACHE UNKNOWN: cache integrity metadata is missing."
        }
        val actual = sha256(payloadText.toByteArray(StandardCharsets.UTF_8))
        require(MessageDigest.isEqual(expected.toByteArray(), actual.toByteArray())) {
            "OFFLINE CACHE UNKNOWN: cache integrity check failed."
        }
        return JSONObject(payloadText)
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
