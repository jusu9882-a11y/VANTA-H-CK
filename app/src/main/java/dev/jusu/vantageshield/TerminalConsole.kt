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

@Composable
fun TerminalConsole(
    checks: List<DeviceCheck>,
    onRefresh: () -> Unit,
    onBack: () -> Unit
) {
    val green = Color(0xFF7CFFB2)
    val muted = Color(0xFF91A5B8)
    var command by remember { mutableStateOf("") }
    var history by remember {
        mutableStateOf(listOf(
            "VANTAGE SHIELD LOCAL CONSOLE v0.1.0",
            "Restricted diagnostic console. No network access or arbitrary shell execution.",
            "Type 'help' to list available commands."
        ))
    }

    fun execute(raw: String) {
        val input = raw.trim()
        if (input.isEmpty()) return
        val response = when (input.lowercase()) {
            "help" -> listOf(
                "help      Show available commands",
                "status    Show latest local device assessment",
                "device    List device posture checks",
                "refresh   Re-read available device posture signals",
                "version   Show console and app version",
                "clear     Clear terminal output",
                "exit      Return to the scanner dashboard",
                "",
                "Only built-in diagnostic commands are supported. This is not /system/bin/sh."
            )
            "status" -> listOf("Device checks: ${checks.size}", "Review UNKNOWN and REVIEW states manually.", "No APK scan is run until an APK is selected in Scanner.")
            "device" -> if (checks.isEmpty()) listOf("No device checks available.") else checks.map { "${it.status.padEnd(7)} ${it.name}: ${it.detail}" }
            "refresh" -> { onRefresh(); listOf("Refresh requested. Return to status/device after the screen updates.") }
            "version" -> listOf("VANTAGE SHIELD 0.1.0", "Console: local restricted diagnostics", "Android minimum: API 26")
            "clear" -> { history = emptyList(); emptyList() }
            "exit" -> { onBack(); listOf("Returning to dashboard…") }
            else -> listOf("Unknown command: $input", "Type 'help' for supported commands.")
        }
        history = (history + listOf("$ $input") + response).takeLast(250)
    }

    Column(
        Modifier.fillMaxSize().background(Color(0xFF050A0D)).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Column {
                Text("SHIELD TERMINAL", color = green, fontFamily = FontFamily.Monospace, fontSize = 19.sp)
                Text("LOCAL DIAGNOSTIC CONSOLE", color = muted, fontSize = 11.sp)
            }
            TextButton(onClick = onBack) { Text("DASHBOARD") }
        }
        LazyColumn(
            Modifier.weight(1f).fillMaxWidth().background(Color(0xFF0B1518), RoundedCornerShape(10.dp)).padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp)
        ) {
            items(history) { line ->
                Text(line, color = if (line.startsWith("$ ")) green else Color(0xFFD0E3D9),
                    fontFamily = FontFamily.Monospace, fontSize = 12.sp)
            }
        }
        Row(
            Modifier.fillMaxWidth().background(Color(0xFF10201B), RoundedCornerShape(9.dp)).padding(horizontal = 10.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text("$", color = green, fontFamily = FontFamily.Monospace)
            BasicTextField(
                value = command,
                onValueChange = { command = it },
                modifier = Modifier.weight(1f),
                singleLine = true,
                textStyle = androidx.compose.ui.text.TextStyle(color = Color.White, fontFamily = FontFamily.Monospace, fontSize = 14.sp),
                decorationBox = { inner ->
                    if (command.isEmpty()) Text("enter command…", color = muted, fontFamily = FontFamily.Monospace, fontSize = 14.sp)
                    inner()
                }
            )
            TextButton(onClick = { val value = command; command = ""; execute(value) }) { Text("RUN", color = green) }
        }
        Text("SAFE MODE • BUILT-IN COMMANDS ONLY • NO ROOT REQUIRED", color = muted, fontSize = 10.sp)
    }
}
