package dev.jusu.vantageshield

/** Deterministic CycloneDX 1.6 JSON export from validated embedded Maven coordinates only. */
object CycloneDxExporter {
    fun render(dependencies: List<DependencyCoordinate>): String {
        val components = dependencies
            .distinctBy { it.purl }
            .sortedBy { it.purl }
            .joinToString(",\n") { dependency ->
                """    {
      "type": "library",
      "bom-ref": "${escape(dependency.purl)}",
      "group": "${escape(dependency.groupId)}",
      "name": "${escape(dependency.artifactId)}",
      "version": "${escape(dependency.version)}",
      "purl": "${escape(dependency.purl)}",
      "properties": [
        {"name": "vantage:evidence:source", "value": "embedded META-INF/maven pom.properties"},
        {"name": "vantage:evidence:path", "value": "${escape(dependency.metadataPath)}"},
        {"name": "vantage:evidence:confidence", "value": "exact-coordinate-metadata"}
      ]
    }"""
            }
        return """{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "VANTAGE SHIELD",
          "version": "0.1.0"
        }
      ]
    },
    "properties": [
      {"name": "vantage:inventory:scope", "value": "validated embedded Maven pom.properties only"},
      {"name": "vantage:inventory:limitation", "value": "Not a complete dependency graph; DEX namespace heuristics are excluded"}
    ]
  },
  "components": [${components}]
}
"""
    }

    private fun escape(value: String): String = buildString(value.length + 8) {
        value.forEach { char ->
            when (char) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (char.code < 0x20) append("\\u%04x".format(char.code)) else append(char)
            }
        }
    }
}
