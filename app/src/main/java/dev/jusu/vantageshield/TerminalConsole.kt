package dev.jusu.vantageshield

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun TerminalConsole(
    checks: List<DeviceCheck>,
    onRefresh: () -> Unit,
    onBack: () -> Unit
) {
    // Terminal colour 2: vivid green, used consistently for console output.
    val green = Color(0xFF00FF66)
    val softGreen = Color(0xFFB7F7CE)
    val muted = Color(0xFF719783)
    var command by remember { mutableStateOf("") }
    var running by remember { mutableStateOf(false) }
    var history by remember {
        mutableStateOf(listOf(
            "VANTAGE SHIELD ANDROID CONSOLE v0.2.0",
            "LOCAL DEVICE • READ-ONLY SYSTEM DIAGNOSTICS",
            "Type 'help' to list built-in and system commands."
        ))
    }
    val scope = rememberCoroutineScope()

    fun append(input: String, lines: List<String>) {
        history = (history + listOf("$ $input") + lines).takeLast(300)
    }

    fun execute(raw: String) {
        if (running) return
        val input = raw.trim()
        if (input.isEmpty()) return
        when (val parsed = TerminalCommandEngine.parse(input)) {
            is TerminalCommandEngine.Parsed.Invalid -> append(input, listOf(parsed.message))
            is TerminalCommandEngine.Parsed.System -> {
                running = true
                history = (history + "$ $input" + listOf("[running ${parsed.label} …]")).takeLast(300)
                scope.launch {
                    val result = withContext(Dispatchers.IO) { TerminalCommandEngine.run(parsed) }
                    history = (history.dropLast(1) + result.lines()).takeLast(300)
                    running = false
                }
            }
            is TerminalCommandEngine.Parsed.BuiltIn -> when (parsed.name) {
                "help" -> append(input, listOf(
                    "BUILT-IN COMMANDS",
                    "help       List commands",
                    "status     Summarize current device posture checks",
                    "device     Show individual device posture checks",
                    "refresh    Re-read available device posture signals",
                    "version    Show app and console version",
                    "clear      Clear terminal output",
                    "exit       Return to the dashboard",
                    "",
                    "ANDROID READ-ONLY COMMANDS",
                    "id         Show the app process identity",
                    "whoami     Show the app process user",
                    "uname      Show Android kernel information",
                    "uptime     Show device uptime",
                    "df         Show filesystem capacity",
                    "ps         List processes visible to this app",
                    "ip addr    Show network interface addresses",
                    "ip route   Show available IP routes",
                    "getprop ro.build.version.release",
                    "getprop ro.build.version.sdk",
                    "getprop ro.build.version.security_patch",
                    "getprop ro.product.manufacturer",
                    "getprop ro.product.model",
                    "",
                    "System commands run as this app's Android UID. No root, shell chaining, scripts, or arbitrary commands."
                ))
                "status" -> append(input, listOf(
                    "Device posture checks: ${checks.size}",
                    "OK: ${checks.count { it.status == "OK" }}",
                    "REVIEW: ${checks.count { it.status == "REVIEW" }}",
                    "UNKNOWN: ${checks.count { it.status == "UNKNOWN" }}",
                    "INFO: ${checks.count { it.status == "INFO" }}",
                    "This is device posture, not a malware scan."
                ))
                "device" -> append(input, if (checks.isEmpty()) listOf("No device checks available.")
                    else checks.map { "${it.status.padEnd(7)} ${it.name}: ${it.detail}" })
                "refresh" -> {
                    onRefresh()
                    append(input, listOf("Device posture refresh requested. Run 'device' again after the dashboard updates."))
                }
                "version" -> append(input, listOf("VANTAGE SHIELD 0.1.0", "Console engine: 0.2.0", "Minimum Android API: 26"))
                "clear" -> history = emptyList()
                "exit" -> {
                    append(input, listOf("Returning to dashboard…"))
                    onBack()
                }
            }
        }
    }

    Column(
        Modifier.fillMaxSize().background(Color(0xFF020805)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Column {
                Text("SHIELD TERMINAL", color = green, fontFamily = FontFamily.Monospace, fontSize = 19.sp)
                Text("ANDROID DIAGNOSTIC CONSOLE • GREEN / COLOUR 2", color = muted, fontSize = 10.sp)
            }
            TextButton(onClick = onBack) { Text("DASHBOARD", color = green) }
        }
        LazyColumn(
            Modifier.weight(1f).fillMaxWidth().background(Color(0xFF06140B), RoundedCornerShape(10.dp)).padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp)
        ) {
            items(history) { line ->
                Text(line, color = if (line.startsWith("$ ")) green else softGreen,
                    fontFamily = FontFamily.Monospace, fontSize = 12.sp)
            }
        }
        Row(
            Modifier.fillMaxWidth().background(Color(0xFF0B2414), RoundedCornerShape(9.dp)).padding(horizontal = 10.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text("$", color = green, fontFamily = FontFamily.Monospace)
            BasicTextField(
                value = command,
                onValueChange = { command = it },
                modifier = Modifier.weight(1f),
                singleLine = true,
                enabled = !running,
                textStyle = androidx.compose.ui.text.TextStyle(color = green, fontFamily = FontFamily.Monospace, fontSize = 14.sp),
                decorationBox = { inner ->
                    if (command.isEmpty()) Text("enter command…", color = muted, fontFamily = FontFamily.Monospace, fontSize = 14.sp)
                    inner()
                }
            )
            TextButton(enabled = !running, onClick = { val value = command; command = ""; execute(value) }) {
                Text(if (running) "RUNNING" else "RUN", color = green)
            }
        }
        Text("READ-ONLY • APP-UID EXECUTION • NO ROOT • NO ARBITRARY SHELL", color = muted, fontSize = 9.sp)
    }
}
