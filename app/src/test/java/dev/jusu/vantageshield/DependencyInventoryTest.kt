package dev.jusu.vantageshield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DependencyInventoryTest {
    @Test fun extractsExactCoordinatesFromMatchingMavenMetadataPath() {
        val path = "META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties"
        val content = "groupId=com.squareup.okhttp3\nartifactId=okhttp\nversion=4.12.0\n"
        val found = DependencyInventory.parse(mapOf(path to content.toByteArray()))
        assertEquals(1, found.size)
        assertEquals("pkg:maven/com.squareup.okhttp3/okhttp@4.12.0", found.single().purl)
    }

    @Test fun rejectsPathCoordinateMismatchAndMissingVersion() {
        val mismatch = "META-INF/maven/com/example/library/pom.properties" to
            "groupId=com.attacker\nartifactId=library\nversion=1.0.0\n".toByteArray()
        val missing = "META-INF/maven/com/example/other/pom.properties" to
            "groupId=com.example\nartifactId=other\n".toByteArray()
        assertTrue(DependencyInventory.parse(mapOf(mismatch, missing)).isEmpty())
    }

    @Test fun ignoresOversizedAndMalformedMetadata() {
        val path = "META-INF/maven/com/example/library/pom.properties"
        val huge = ByteArray(65 * 1024) { 65 }
        val malformed = byteArrayOf(0xc3.toByte(), 0x28)
        assertTrue(DependencyInventory.parse(mapOf(path to huge, "META-INF/maven/com/example/other/pom.properties" to malformed)).isEmpty())
    }

    @Test fun ignoresNonPomMetadataFiles() {
        val content = "groupId=com.example\nartifactId=library\nversion=1.2.3\n".toByteArray()
        val one = "META-INF/maven/com.example/library/pom.properties"
        assertEquals(1, DependencyInventory.parse(mapOf(one to content, one + ".copy" to content)).size)
    }
}
