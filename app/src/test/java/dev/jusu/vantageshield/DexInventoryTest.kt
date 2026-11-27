package dev.jusu.vantageshield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DexInventoryTest {
    private fun minimalDex(descriptor: String): ByteArray {
        val encoded = descriptor.toByteArray(Charsets.UTF_8)
        val stringDataOffset = 152
        val bytes = ByteArray(stringDataOffset + 1 + encoded.size + 1)
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        bytes[0] = 0x64; bytes[1] = 0x65; bytes[2] = 0x78; bytes[3] = 0x0a
        bytes[4] = 0x30; bytes[5] = 0x33; bytes[6] = 0x35; bytes[7] = 0
        b.putInt(32, bytes.size); b.putInt(36, 112); b.putInt(40, 0x12345678)
        b.putInt(56, 1); b.putInt(60, 112)
        b.putInt(64, 1); b.putInt(68, 116)
        b.putInt(96, 1); b.putInt(100, 120)
        b.putInt(112, stringDataOffset); b.putInt(116, 0); b.putInt(120, 0)
        bytes[stringDataOffset] = encoded.size.toByte()
        encoded.copyInto(bytes, stringDataOffset + 1)
        bytes[bytes.lastIndex] = 0
        return bytes
    }

    @Test fun identifiesLibraryFromActualClassDefinition() {
        val hits = DexInventory.inspect(minimalDex("Lokhttp3/OkHttpClient;"))
        assertEquals(listOf(DexLibraryHit("OkHttp", 1)), hits)
    }

    @Test fun rejectsBadMagicAndOutOfBoundsTables() {
        assertNull(DexInventory.inspect(ByteArray(160)))
        val malformed = minimalDex("Lexample/App;")
        ByteBuffer.wrap(malformed).order(ByteOrder.LITTLE_ENDIAN).putInt(60, Int.MAX_VALUE)
        assertNull(DexInventory.inspect(malformed))
    }

    @Test fun reportsMalformedDexWithoutCallingItAVulnerability() {
        val findings = DexInventory.audit(listOf("classes.dex" to byteArrayOf(1, 2, 3)))
        assertTrue(findings.any { it.title == "DEX structure unavailable" && it.severity == Severity.LOW })
        assertTrue(findings.none { it.severity == Severity.HIGH || it.severity == Severity.CRITICAL })
    }

    @Test fun unknownNamespacesDoNotInventDependencyNames() {
        assertTrue(DexInventory.inspect(minimalDex("Lexample/Unknown;"))!!.isEmpty())
    }
}
