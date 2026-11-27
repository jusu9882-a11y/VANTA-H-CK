package dev.jusu.vantageshield

import java.util.Properties

data class DependencyCoordinate(
    val groupId: String,
    val artifactId: String,
    val version: String,
    val metadataPath: String
) {
    val purl: String get() = "pkg:maven/$groupId/$artifactId@$version"
}

/** Extracts exact Maven coordinates only from embedded Maven pom.properties metadata. */
object DependencyInventory {
    private val coordinatePart = Regex("[A-Za-z0-9_.+-]{1,200}")

    fun parse(metadata: Map<String, ByteArray>): List<DependencyCoordinate> {
        val found = linkedMapOf<String, DependencyCoordinate>()
        metadata.toSortedMap().forEach { (path, bytes) ->
            if (!path.startsWith("META-INF/maven/") ||
                !path.endsWith("/pom.properties", ignoreCase = true) ||
                bytes.size > 64 * 1024) return@forEach
            val properties = Properties()
            runCatching { bytes.inputStream().use(properties::load) }.getOrElse { return@forEach }
            val group = properties.getProperty("groupId")?.trim().orEmpty()
            val artifact = properties.getProperty("artifactId")?.trim().orEmpty()
            val version = properties.getProperty("version")?.trim().orEmpty()
            if (!coordinatePart.matches(group) || !coordinatePart.matches(artifact) ||
                !coordinatePart.matches(version)) return@forEach
            val pathParts = path.removePrefix("META-INF/maven/").removeSuffix("/pom.properties").split("/")
            if (pathParts.size < 2) return@forEach
            if (pathParts[pathParts.lastIndex] != artifact ||
                pathParts.dropLast(1).joinToString(".") != group) return@forEach
            val coordinate = DependencyCoordinate(group, artifact, version, path)
            found.putIfAbsent(coordinate.purl, coordinate)
        }
        return found.values.toList()
    }

    fun audit(metadata: Map<String, ByteArray>): List<Finding> {
        val coordinates = parse(metadata)
        if (coordinates.isEmpty()) return emptyList()
        return listOf(Finding(
            "Exact Maven dependency coordinates recovered",
            Severity.INFO,
            "Recovered " + coordinates.size + " Maven coordinate(s) from embedded pom.properties: " +
                coordinates.take(20).joinToString { it.purl } +
                if (coordinates.size > 20) " and more." else "" +
                " Metadata provenance is embedded APK content; this is not proof every listed artifact is reachable at runtime.",
            "Use the coordinates and versions as SBOM inputs. Check them against a current, trusted advisory database; this build does not claim CVE coverage."
        ))
    }
}
