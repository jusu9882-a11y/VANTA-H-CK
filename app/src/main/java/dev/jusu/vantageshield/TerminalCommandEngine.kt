package dev.jusu.vantageshield

import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * A deliberately small Android diagnostic command interpreter.
 * Commands are mapped to fixed executable/argument arrays; no shell is invoked.
 */
object TerminalCommandEngine {
    sealed class Parsed {
        data class BuiltIn(val name: String) : Parsed()
        data class System(val label: String, val argv: List<String>) : Parsed()
        data class Invalid(val message: String) : Parsed()
    }

    private val properties = setOf(
        "ro.build.version.release",
        "ro.build.version.sdk",
        "ro.build.version.security_patch",
        "ro.product.manufacturer",
        "ro.product.model"
    )

    fun parse(raw: String): Parsed {
        val parts = raw.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (parts.isEmpty()) return Parsed.Invalid("Enter a command.")
        val name = parts.first().lowercase()
        if (name in setOf("help", "status", "device", "refresh", "version", "clear", "exit")) {
            return if (parts.size == 1) Parsed.BuiltIn(name)
            else Parsed.Invalid("The '$name' command does not accept arguments.")
        }
        val toybox = "/system/bin/toybox"
        return when (name) {
            "id", "uname", "df", "uptime", "ps", "whoami" ->
                if (parts.size == 1) Parsed.System(name, listOf(toybox, name))
                else Parsed.Invalid("'$name' does not accept arguments.")
            "ip" -> if (parts.size == 2 && parts[1] in setOf("addr", "route"))
                Parsed.System("ip ${parts[1]}", listOf(toybox, "ip", parts[1]))
                else Parsed.Invalid("Usage: ip addr | ip route")
            "getprop" -> if (parts.size == 2 && parts[1] in properties)
                Parsed.System("getprop ${parts[1]}", listOf("/system/bin/getprop", parts[1]))
                else Parsed.Invalid("Usage: getprop <approved-property>. Use 'help' to see allowed properties.")
            else -> Parsed.Invalid("Command not available: ${parts.first()}. Type 'help' for supported commands.")
        }
    }

    fun run(command: Parsed.System): String {
        val process = try {
            ProcessBuilder(command.argv).redirectErrorStream(true).start()
        } catch (e: Exception) {
            return "Could not start ${command.label}: ${e.message ?: "system command unavailable"}"
        }
        val reader = Executors.newSingleThreadExecutor()
        return try {
            val output = reader.submit<String> {
                val result = StringBuilder()
                process.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { line ->
                        if (result.length < 12_000) result.append(line.take(500)).append('\n')
                    }
                }
                result.toString().take(12_000)
            }
            if (!process.waitFor(3, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                "Command timed out after 3 seconds."
            } else {
                val text = runCatching { output.get(600, TimeUnit.MILLISECONDS) }
                    .getOrElse { "Command output could not be read: ${it.message}" }
                if (text.isBlank()) "(no output; exit code ${process.exitValue()})" else text.trimEnd()
            }
        } catch (e: Exception) {
            process.destroyForcibly()
            "Command failed: ${e.message ?: "unknown error"}"
        } finally {
            reader.shutdownNow()
        }
    }
}
