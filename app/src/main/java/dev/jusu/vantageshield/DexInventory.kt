package dev.jusu.vantageshield

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class DexLibraryHit(val library: String, val classCount: Int)

/** Bounded structural DEX reader. Inventories class descriptors; never executes bytecode. */
object DexInventory {
    private const val HEADER_SIZE = 112
    private const val MAX_ITEMS = 1_000_000
    private val libraries = listOf(
        "OkHttp" to listOf("Lokhttp3/"), "Retrofit" to listOf("Lretrofit2/"),
        "Gson" to listOf("Lcom/google/gson/"), "Moshi" to listOf("Lcom/squareup/moshi/"),
        "AndroidX" to listOf("Landroidx/"), "Kotlin stdlib" to listOf("Lkotlin/"),
        "Kotlin coroutines" to listOf("Lkotlinx/coroutines/"),
        "Dagger" to listOf("Ldagger/"), "Hilt" to listOf("Ldagger/hilt/"),
        "RxJava" to listOf("Lio/reactivex/"), "Ktor" to listOf("Lio/ktor/"),
        "Bouncy Castle" to listOf("Lorg/bouncycastle/"),
        "Apache Commons" to listOf("Lorg/apache/commons/")
    )

    fun inspect(bytes: ByteArray): List<DexLibraryHit>? {
        if (bytes.size < HEADER_SIZE || !bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(0x64, 0x65, 0x78, 0x0a))) return null
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        if (b.getInt(40) != 0x12345678) return null
        val stringCount = b.getInt(56); val stringOffset = b.getInt(60)
        val typeCount = b.getInt(64); val typeOffset = b.getInt(68)
        val classCount = b.getInt(96); val classOffset = b.getInt(100)
        if (!validTable(stringCount, stringOffset, 4, bytes.size) ||
            !validTable(typeCount, typeOffset, 4, bytes.size) ||
            !validTable(classCount, classOffset, 32, bytes.size)) return null

        val strings = ArrayList<String>(stringCount)
        repeat(stringCount) { i ->
            val dataOffset = b.getInt(stringOffset + i * 4)
            if (dataOffset !in HEADER_SIZE until bytes.size) return null
            val length = readUleb(b, dataOffset) ?: return null
            var p = length.second
            val start = p
            while (p < bytes.size && bytes[p].toInt() != 0) p++
            if (p >= bytes.size || p - start > 1_000_000) return null
            strings += String(bytes, start, p - start, Charsets.UTF_8)
        }
        val descriptors = IntArray(typeCount)
        repeat(typeCount) { i ->
            val stringIndex = b.getInt(typeOffset + i * 4)
            if (stringIndex !in strings.indices) return null
            descriptors[i] = stringIndex
        }
        val counts = linkedMapOf<String, Int>()
        repeat(classCount) { i ->
            val classIndex = b.getInt(classOffset + i * 32)
            if (classIndex !in descriptors.indices) return null
            val descriptor = strings[descriptors[classIndex]]
            libraries.firstOrNull { pair -> pair.second.any(descriptor::startsWith) }?.let { hit ->
                counts[hit.first] = (counts[hit.first] ?: 0) + 1
            }
        }
        return counts.map { DexLibraryHit(it.key, it.value) }
    }

    fun audit(dexFiles: List<Pair<String, ByteArray>>): List<Finding> {
        if (dexFiles.isEmpty()) return emptyList()
        val valid = dexFiles.mapNotNull { pair -> inspect(pair.second)?.let { pair.first to it } }
        val invalidCount = dexFiles.size - valid.size
        val totals = valid.flatMap { it.second }.groupBy { it.library }
            .mapValues { entry -> entry.value.sumOf { it.classCount } }.toSortedMap()
        return buildList {
            if (totals.isNotEmpty()) add(Finding(
                "DEX library namespace inventory", Severity.INFO,
                "Validated " + valid.size + " DEX file(s). Recognized class definitions: " +
                    totals.entries.joinToString { it.key + " (" + it.value + " classes)" } +
                    ". Namespace matching is an inventory lead, not proof of exact artifact coordinates or version.",
                "Resolve exact Maven coordinates and versions from build metadata or a generated SBOM before checking advisories. Review shaded, relocated, and unrecognized libraries separately."
            ))
            if (invalidCount > 0) add(Finding(
                "DEX structure unavailable", Severity.LOW,
                invalidCount.toString() + " DEX-like file(s) did not pass structural validation; their bytecode was not inventoried.",
                "Verify the APK archive and inspect the affected DEX file with a maintained Android reverse-engineering tool."
            ))
        }
    }

    private fun validTable(count: Int, offset: Int, width: Int, size: Int): Boolean =
        count in 0..MAX_ITEMS && (count == 0 && offset == 0 ||
            (offset >= HEADER_SIZE && offset.toLong() + count.toLong() * width <= size))

    private fun readUleb(b: ByteBuffer, offset: Int): Pair<Int, Int>? {
        var result = 0; var shift = 0; var p = offset
        repeat(5) {
            if (p >= b.limit()) return null
            val value = b.get(p++).toInt() and 0xff
            result = result or ((value and 0x7f) shl shift)
            if (value and 0x80 == 0) return result to p
            shift += 7
        }
        return null
    }
}
