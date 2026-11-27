package dev.jusu.vantageshield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TerminalCommandEngineTest {
    @Test fun parsesBuiltInCommands() {
        assertEquals(
            TerminalCommandEngine.Parsed.BuiltIn("status"),
            TerminalCommandEngine.parse("status")
        )
    }

    @Test fun registersAppSpecificSecurityCommands() {
        assertEquals(TerminalCommandEngine.Parsed.BuiltIn("scan"), TerminalCommandEngine.parse("scan"))
        assertEquals(TerminalCommandEngine.Parsed.BuiltIn("findings"), TerminalCommandEngine.parse("findings"))
    }

    @Test fun mapsSystemCommandsToFixedExecutables() {
        val parsed = TerminalCommandEngine.parse("id")
        assertTrue(parsed is TerminalCommandEngine.Parsed.System)
        assertEquals(
            listOf("/system/bin/toybox", "id"),
            (parsed as TerminalCommandEngine.Parsed.System).argv
        )
    }

    @Test fun allowsOnlyApprovedGetpropKeys() {
        assertTrue(TerminalCommandEngine.parse("getprop ro.build.version.sdk") is TerminalCommandEngine.Parsed.System)
        assertTrue(TerminalCommandEngine.parse("getprop ro.serialno") is TerminalCommandEngine.Parsed.Invalid)
    }

    @Test fun rejectsShellMetacharactersAndUnknownCommands() {
        assertTrue(TerminalCommandEngine.parse("id; rm -rf /") is TerminalCommandEngine.Parsed.Invalid)
        assertTrue(TerminalCommandEngine.parse("sh") is TerminalCommandEngine.Parsed.Invalid)
        assertTrue(TerminalCommandEngine.parse("cat /data/data/private") is TerminalCommandEngine.Parsed.Invalid)
    }

    @Test fun restrictsIpSubcommands() {
        assertTrue(TerminalCommandEngine.parse("ip addr") is TerminalCommandEngine.Parsed.System)
        assertTrue(TerminalCommandEngine.parse("ip neigh") is TerminalCommandEngine.Parsed.Invalid)
    }
}
