package dev.jusu.vantageshield

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { ShieldApp() }
    }

    @Composable
    private fun ShieldApp() {
        var report by remember { mutableStateOf<ScanReport?>(null) }
        var checks by remember { mutableStateOf(DeviceChecks.run(this)) }
        var busy by remember { mutableStateOf(false) }
        var showTerminal by remember { mutableStateOf(false) }
        var message by remember { mutableStateOf("Select the Vantage APK to start a local assessment.") }
        val scope = rememberCoroutineScope()
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
            if (uri != null) {
                busy = true
                message = "Inspecting APK locally…"
                scope.launch {
                    try {
                        val result = withContext(Dispatchers.IO) {
                            contentResolver.openInputStream(uri)?.use {
                                ApkScanner.scan(it, uri.lastPathSegment ?: "selected.apk")
                            } ?: error("Unable to open selected file.")
                        }
                        report = result
                        message = "Scan completed. Validate findings before treating them as vulnerabilities."
                    } catch (e: Exception) {
                        message = "Scan failed: ${e.message ?: "unknown error"}"
                    } finally { busy = false }
                }
            }
        }

        MaterialTheme(colorScheme = darkColorScheme(
            primary = Color(0xFF43D9FF),
            background = Color(0xFF080D14),
            surface = Color(0xFF111B27)
        )) {
            if (showTerminal) {
                TerminalConsole(
                    checks = checks,
                    report = report,
                    onRefresh = { checks = DeviceChecks.run(this@MainActivity) },
                    onBack = { showTerminal = false }
                )
            } else {
                Scaffold(containerColor = MaterialTheme.colorScheme.background) { padding ->
                    LazyColumn(
                        Modifier.fillMaxSize().padding(padding).padding(18.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        item {
                            Text("VANTAGE SHIELD", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
                            Text("OFFLINE ANDROID SECURITY LAB", style = MaterialTheme.typography.labelMedium)
                            Text("Independent assessment • Local analysis • No cloud upload", style = MaterialTheme.typography.bodySmall)
                            Spacer(Modifier.height(8.dp))
                            OutlinedButton(onClick = { showTerminal = true }, modifier = Modifier.fillMaxWidth()) {
                                Text("> OPEN TERMINAL")
                            }
                        }
                        item {
                            Card {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                                    Text("APK SECURITY SCAN", style = MaterialTheme.typography.titleLarge)
                                    Text("Choose the Vantage APK using Android's file picker. The file stays on this device.")
                                    Button(
                                        onClick = { picker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) },
                                        enabled = !busy
                                    ) { Text("SELECT APK") }
                                    if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                                    Text(message, style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                        report?.let { r ->
                            item {
                                Card { Column(Modifier.padding(15.dp)) {
                                    Text("ASSESSMENT RESULTS", style = MaterialTheme.typography.titleLarge)
                                    Text(r.fileName)
                                    Text("${r.inspectedEntries} archive entries inspected • ${r.riskCount} review findings")
                                } }
                            }
                            items(r.findings) { f ->
                                Card { Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                                    Text("${f.severity} • ${f.title}", style = MaterialTheme.typography.titleMedium)
                                    Text(f.evidence, style = MaterialTheme.typography.bodySmall)
                                    Text("RECOMMENDATION", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium)
                                    Text(f.recommendation, style = MaterialTheme.typography.bodySmall)
                                } }
                            }
                        }
                        item {
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("DEVICE POSTURE", style = MaterialTheme.typography.titleLarge)
                                TextButton(onClick = { checks = DeviceChecks.run(this@MainActivity) }) { Text("REFRESH") }
                            }
                        }
                        items(checks) { c ->
                            Card { Column(Modifier.padding(12.dp)) {
                                Text("${c.status} • ${c.name}", style = MaterialTheme.typography.titleSmall)
                                Text(c.detail, style = MaterialTheme.typography.bodySmall)
                            } }
                        }
                        item {
                            Text("LIMITATIONS", style = MaterialTheme.typography.titleMedium)
                            Text(
                                "This release performs passive APK triage and local device posture checks. It does not fully decode binary manifests, inspect all native code, prove cryptographic correctness, or run Bluetooth/Wi-Fi penetration tests. A clean result is not a security certification.",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }
        }
    }
}
