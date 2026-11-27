package dev.jusu.vantageshield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CycloneDxExporterTest {
    @Test fun emitsCycloneDx16AndOnlyValidatedMavenComponents() {
        val dependency = DependencyCoordinate(
            "com.squareup.okhttp3", "okhttp", "4.12.0",
            "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties"
        )
        val json = CycloneDxExporter.render(listOf(dependency))
        assertTrue(json.contains("\"bomFormat\": \"CycloneDX\""))
        assertTrue(json.contains("\"specVersion\": \"1.6\""))
        assertTrue(json.contains("\"purl\": \"pkg:maven/com.squareup.okhttp3/okhttp@4.12.0\""))
        assertTrue(json.contains("embedded META-INF/maven pom.properties"))
        assertTrue(json.contains("DEX namespace heuristics are excluded"))
    }

    @Test fun emptyInventoryProducesValidEmptyComponentsArray() {
        val json = CycloneDxExporter.render(emptyList())
        assertTrue(json.contains("\"components\": []"))
        assertTrue(json.trim().startsWith("{"))
        assertTrue(json.trim().endsWith("}"))
    }

    @Test fun outputIsDeterministicAndDeduplicatesPurls() {
        val a = DependencyCoordinate("org.example", "alpha", "1.0", "META-INF/maven/org.example/alpha/pom.properties")
        val b = DependencyCoordinate("org.example", "beta", "2.0", "META-INF/maven/org.example/beta/pom.properties")
        val first = CycloneDxExporter.render(listOf(b, a, a))
        val second = CycloneDxExporter.render(listOf(a, b))
        assertEquals(first, second)
        assertEquals(1, first.split("\\\"name\\\": \\\"alpha\\\"").size - 1)
    }

    @Test fun escapesJsonControlCharactersAndQuotes() {
        val dependency = DependencyCoordinate(
            "org.example", "lib", "1.0",
            "META-INF/maven/org.example/lib/\"quoted\"\\path\n/pom.properties"
        )
        val json = CycloneDxExporter.render(listOf(dependency))
        assertTrue(json.contains("\\\"quoted\\\""))
        assertTrue(json.contains("\\\\path\\n"))
    }
}
