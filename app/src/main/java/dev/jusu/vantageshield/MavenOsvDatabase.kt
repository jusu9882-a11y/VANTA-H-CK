package dev.jusu.vantageshield

import org.apache.maven.artifact.versioning.ComparableVersion
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.zip.ZipFile

data class MavenDatabaseStatus(
    val downloadedAt: String,
    val sourceLastModified: String?,
    val etag: String?,
    val archiveBytes: Long,
    val recordCount: Int,
    val sha256: String,
    val stale: Boolean
)

data class MavenDatabaseCheck(
    val status: MavenDatabaseStatus,
    val advisories: List<OsvAdvisory>,
    val scannedPackages: Int,
    val unsupportedRangeRecords: Int
) {
    val coverageComplete: Boolean get() = !status.stale && unsupportedRangeRecords == 0
}

/**
 * Full Maven-ecosystem OSV archive. The ZIP is kept compressed in app-private storage;
 * no archive entry is extracted to a filesystem path. All ZIP paths, sizes, counts,
 * compression ratios, record IDs and JSON shapes are checked before a snapshot is
 * activated. SHA-256 is a local integrity check, not a publisher signature.
 */
object MavenOsvDatabase {
    private const val SOURCE = "https://storage.googleapis.com/osv-vulnerabilities/Maven/all.zip"
    private const val ARCHIVE = "osv-maven-all.zip"
    private const val META = "osv-maven-all.meta.json"
    private const val MAX_ARCHIVE_BYTES = 64L * 1024 * 1024
    private const val MAX_ENTRY_BYTES = 4L * 1024 * 1024
    private const val MAX_TOTAL_EXPANDED_BYTES = 128L * 1024 * 1024
    private const val MAX_ENTRIES = 100_000
    private const val MAX_COMPRESSION_RATIO = 100L
    private val staleAfter = Duration.ofDays(30)

    fun download(directory: File): MavenDatabaseStatus {
        if (!directory.exists() && !directory.mkdirs()) error("Cannot create private OSV database directory.")
        val temp = File(directory, "$ARCHIVE.part")
        val target = File(directory, ARCHIVE)
        val connection = (URL(SOURCE).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 30_000
            instanceFollowRedirects = true
            setRequestProperty("Accept", "application/zip")
            setRequestProperty("User-Agent", "VANTAGE-SHIELD-Android")
        }
        var lastModified: String? = null
        var etag: String? = null
        try {
            val status = connection.responseCode
            require(status in 200..299) { "OSV Maven archive download returned HTTP $status." }
            require(connection.url.protocol == "https") { "OSV archive redirected away from HTTPS." }
            val declaredLength = connection.getHeaderFieldLong("Content-Length", -1L)
            require(declaredLength in -1L..MAX_ARCHIVE_BYTES) { "OSV Maven archive exceeds the 64 MiB download limit." }
            lastModified = connection.getHeaderField("Last-Modified")
            etag = connection.getHeaderField("ETag")
            FileOutputStream(temp).use { output ->
                connection.inputStream.use { input ->
                    val buffer = ByteArray(32 * 1024)
                    var total = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        require(total <= MAX_ARCHIVE_BYTES) { "OSV Maven archive exceeded the 64 MiB download limit." }
                        output.write(buffer, 0, count)
                    }
                    require(total > 0L && (declaredLength < 0L || total == declaredLength)) {
                        "OSV Maven archive download was empty or incomplete."
                    }
                }
                output.flush()
                output.fd.sync()
            }
        } catch (e: Exception) {
            temp.delete()
            throw e
        } finally {
            connection.disconnect()
        }

        try {
            val validated = validateArchive(temp)
            val digest = sha256(temp)
            val metadata = JSONObject()
                .put("schemaVersion", 1)
                .put("source", SOURCE)
                .put("downloadedAt", Instant.now().toString())
                .put("sourceLastModified", lastModified ?: JSONObject.NULL)
                .put("etag", etag ?: JSONObject.NULL)
                .put("archiveBytes", temp.length())
                .put("recordCount", validated)
                .put("sha256", digest)
            val metaTemp = File(directory, "$META.part")
            metaTemp.writeText(metadata.toString(), Charsets.UTF_8)
            FileOutputStream(metaTemp, true).use { it.fd.sync() }
            val metadataTarget = File(directory, META)
            val archiveBackup = File(directory, "$ARCHIVE.previous")
            val metadataBackup = File(directory, "$META.previous")
            archiveBackup.delete()
            metadataBackup.delete()
            var installedArchive = false
            var installedMetadata = false
            try {
                if (target.exists() && !target.renameTo(archiveBackup)) error("Cannot preserve the previous Maven database snapshot.")
                if (metadataTarget.exists() && !metadataTarget.renameTo(metadataBackup)) error("Cannot preserve the previous Maven database metadata.")
                Files.move(temp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                installedArchive = true
                Files.move(metaTemp.toPath(), metadataTarget.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                installedMetadata = true
                val verified = status(directory)
                archiveBackup.delete()
                metadataBackup.delete()
                return verified
            } catch (e: Exception) {
                if (installedArchive) target.delete()
                if (installedMetadata) metadataTarget.delete()
                if (archiveBackup.exists()) archiveBackup.renameTo(target)
                if (metadataBackup.exists()) metadataBackup.renameTo(metadataTarget)
                throw e
            }
        } catch (e: Exception) {
            temp.delete()
            throw e
        }
    }

    fun status(directory: File, now: Instant = Instant.now()): MavenDatabaseStatus {
        val archive = File(directory, ARCHIVE)
        val metaFile = File(directory, META)
        require(archive.isFile && metaFile.isFile) { "FULL MAVEN DATABASE UNKNOWN: download the OSV Maven archive first." }
        require(archive.length() in 1..MAX_ARCHIVE_BYTES) { "FULL MAVEN DATABASE UNKNOWN: archive size is invalid." }
        val meta = JSONObject(metaFile.readText(Charsets.UTF_8))
        require(meta.optInt("schemaVersion", -1) == 1 && meta.optString("source") == SOURCE) {
            "FULL MAVEN DATABASE UNKNOWN: unsupported metadata or source."
        }
        val expected = meta.optString("sha256")
        require(expected.matches(Regex("[a-f0-9]{64}")) && MessageDigest.isEqual(
            expected.toByteArray(), sha256(archive).toByteArray()
        )) { "FULL MAVEN DATABASE UNKNOWN: archive integrity check failed." }
        val downloaded = Instant.parse(meta.getString("downloadedAt"))
        return MavenDatabaseStatus(
            downloadedAt = downloaded.toString(),
            sourceLastModified = meta.optString("sourceLastModified").takeIf { it.isNotBlank() && it != "null" },
            etag = meta.optString("etag").takeIf { it.isNotBlank() && it != "null" },
            archiveBytes = archive.length(),
            recordCount = meta.optInt("recordCount"),
            sha256 = expected,
            stale = Duration.between(downloaded, now).let { !it.isNegative && it > staleAfter }
        )
    }

    fun check(directory: File, dependencies: List<DependencyCoordinate>): MavenDatabaseCheck {
        val status = status(directory)
        val unique = dependencies.distinctBy { it.purl }.sortedBy { it.purl }
        require(unique.isNotEmpty()) { "No exact Maven coordinates are available for local database matching." }
        val byIdentity = unique.associateBy { it.groupId + ":" + it.artifactId }
        val matches = linkedMapOf<String, MutableList<String>>()
        val unsupported = linkedSetOf<String>()
        ZipFile(File(directory, ARCHIVE)).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory) continue
                val name = entry.name
                if (!name.endsWith(".json") || name.contains("/") || name.contains("\\") || name.startsWith(".")) {
                    error("OSV archive contains an unexpected entry path.")
                }
                val bytes = zip.getInputStream(entry).use { input ->
                    val output = java.io.ByteArrayOutputStream()
                    val buffer = ByteArray(8192)
                    var countTotal = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        countTotal += count
                        require(countTotal <= MAX_ENTRY_BYTES) { "OSV advisory entry exceeds the 4 MiB limit." }
                        output.write(buffer, 0, count)
                    }
                    output.toByteArray()
                }
                val record = JSONObject(String(bytes, StandardCharsets.UTF_8))
                val id = record.optString("id")
                require(id.isNotBlank() && name == "$id.json") { "OSV archive advisory filename/ID mismatch." }
                if (record.has("withdrawn") && !record.isNull("withdrawn")) continue
                val affected = record.optJSONArray("affected") ?: continue
                for (i in 0 until affected.length()) {
                    val item = affected.optJSONObject(i) ?: continue
                    val pkg = item.optJSONObject("package") ?: continue
                    if (pkg.optString("ecosystem") != "Maven") continue
                    val dependency = byIdentity[pkg.optString("name")] ?: continue
                    val version = dependency.version
                    val versions = item.optJSONArray("versions")
                    var hit = false
                    if (versions != null) {
                        val candidateVersion = parseMavenVersion(version)
                        for (v in 0 until versions.length()) {
                            val listedVersion = parseMavenVersion(versions.optString(v))
                            if (candidateVersion != null && listedVersion != null && candidateVersion.compareTo(listedVersion) == 0) {
                                hit = true
                            } else if (listedVersion == null) {
                                unsupported += "$id (invalid explicit Maven version)"
                            }
                        }
                    }
                    val ranges = item.optJSONArray("ranges")
                    if ((versions == null || versions.length() == 0) && (ranges == null || ranges.length() == 0)) {
                        unsupported += "$id (no affected version data)"
                    }
                    if (!hit && ranges != null) {
                        for (rangeIndex in 0 until ranges.length()) {
                            val range = ranges.optJSONObject(rangeIndex) ?: continue
                            val type = range.optString("type")
                            if (type != "ECOSYSTEM") {
                                unsupported += "$id ($type)"
                                continue
                            }
                            val events = range.optJSONArray("events")
                            if (events == null || events.length() == 0) {
                                unsupported += "$id (missing events)"
                                continue
                            }
                            val result = rangeAffects(events, version)
                            if (result == null) unsupported += "$id (unreadable Maven range)"
                            else if (result) hit = true
                        }
                    }
                    if (hit) matches.getOrPut(id) { mutableListOf() }.add(dependency.purl)
                }
            }
        }
        val advisories = matches.mapNotNull { (id, purls) ->
            val entry = ZipFile(File(directory, ARCHIVE)).use { zip ->
                zip.getInputStream(zip.getEntry("$id.json")).bufferedReader().use { it.readText() }
            }
            OsvClient.parseAdvisory(JSONObject(entry), id, purls.distinct())
        }.distinctBy { it.id }.sortedBy { it.id }
        return MavenDatabaseCheck(status, advisories, unique.size, unsupported.size)
    }

    internal fun rangeAffects(events: org.json.JSONArray, version: String): Boolean? {
        if (events.length() == 0) return null
        val candidate = parseMavenVersion(version) ?: return null
        var lower: ComparableVersion? = null
        var active = false
        var matched = false
        for (i in 0 until events.length()) {
            val event = events.optJSONObject(i) ?: return null
            val introduced = event.optString("introduced").takeIf { it.isNotBlank() }
            val fixed = event.optString("fixed").takeIf { it.isNotBlank() }
            val last = event.optString("last_affected").takeIf { it.isNotBlank() }
            val limit = event.optString("limit").takeIf { it.isNotBlank() }
            if (listOf(introduced, fixed, last, limit).count { it != null } != 1) return null
            when {
                introduced != null -> {
                    if (active) return null
                    lower = if (introduced == "0") null else parseMavenVersion(introduced) ?: return null
                    active = true
                }
                fixed != null -> {
                    if (!active) return null
                    val upper = parseMavenVersion(fixed) ?: return null
                    if (lower != null && upper < lower!!) return null
                    if ((lower == null || candidate >= lower!!) && candidate < upper) matched = true
                    active = false
                }
                last != null -> {
                    if (!active) return null
                    val upper = parseMavenVersion(last) ?: return null
                    if (lower != null && upper < lower!!) return null
                    if ((lower == null || candidate >= lower!!) && candidate <= upper) matched = true
                    active = false
                }
                limit != null -> {
                    if (!active) return null
                    val upper = parseMavenVersion(limit) ?: return null
                    if (lower != null && upper < lower!!) return null
                    if ((lower == null || candidate >= lower!!) && candidate < upper) matched = true
                    active = false
                }
            }
        }
        if (active && (lower == null || candidate >= lower!!)) matched = true
        return matched
    }

    private fun parseMavenVersion(value: String): ComparableVersion? {
        if (value.length !in 1..128 || !value.matches(Regex("[A-Za-z0-9][A-Za-z0-9._+!-]*"))) return null
        return runCatching { ComparableVersion(value) }.getOrNull()
    }

    internal fun validateArchive(file: File): Int {
        require(file.length() in 1..MAX_ARCHIVE_BYTES) { "OSV Maven archive size is invalid." }
        var count = 0
        var expanded = 0L
        ZipFile(file).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory) continue
                count++
                require(count <= MAX_ENTRIES) { "OSV archive contains too many entries." }
                require(entry.name.endsWith(".json") && !entry.name.contains("/") &&
                    !entry.name.contains("\\") && !entry.name.startsWith(".")) {
                    "OSV archive contains an unsafe entry path."
                }
                require(entry.size in 1..MAX_ENTRY_BYTES && entry.compressedSize >= 0L) {
                    "OSV archive entry size is invalid."
                }
                require(entry.size <= maxOf(1L, entry.compressedSize) * MAX_COMPRESSION_RATIO) {
                    "OSV archive entry compression ratio is unsafe."
                }
                expanded += entry.size
                require(expanded <= MAX_TOTAL_EXPANDED_BYTES) { "OSV archive expands beyond the 128 MiB safety limit." }
                val bytes = zip.getInputStream(entry).use { input ->
                    val output = java.io.ByteArrayOutputStream()
                    val buffer = ByteArray(8192)
                    var total = 0L
                    while (true) {
                        val n = input.read(buffer)
                        if (n < 0) break
                        total += n
                        require(total <= MAX_ENTRY_BYTES) { "OSV archive entry exceeded its size limit." }
                        output.write(buffer, 0, n)
                    }
                    output.toByteArray()
                }
                val record = JSONObject(String(bytes, StandardCharsets.UTF_8))
                require(record.optString("id").isNotBlank() && entry.name == record.optString("id") + ".json") {
                    "OSV archive advisory filename/ID mismatch."
                }
            }
        }
        require(count > 0) { "OSV Maven archive contains no advisory records." }
        return count
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(32 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
