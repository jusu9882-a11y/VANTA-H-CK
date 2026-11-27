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
        var osvResult by remember { mutableStateOf<OsvCheckResult?>(null) }
        var osvError by remember { mutableStateOf<String?>(null) }
        var osvBusy by remember { mutableStateOf(false) }
        var checks by remember { mutableStateOf(DeviceChecks.run(this)) }
        var busy by remember { mutableStateOf(false) }
        var showTerminal by remember { mutableStateOf(false) }
        var message by remember { mutableStateOf("Select the Vantage APK to start a local assessment.") }
        val scope = rememberCoroutineScope()
        val sbomExporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.cyclonedx+json")) { uri: Uri? ->
            if (uri != null) {
                val dependencies = report?.dependencies.orEmpty()
                scope.launch {
                    try {
                        val json = CycloneDxExporter.render(dependencies)
                        withContext(Dispatchers.IO) {
                            contentResolver.openOutputStream(uri)?.bufferedWriter(Charsets.UTF_8)?.use { it.write(json) }
                                ?: error("Unable to create the SBOM document.")
                        }
                        message = "CycloneDX SBOM exported: ${dependencies.size} verified Maven component(s)."
                    } catch (e: Exception) {
                        message = "SBOM export failed: ${e.message ?: "unknown error"}"
                    }
                }
            }
        }
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
                        osvResult = null
                        osvError = null
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
                            Text("LOCAL APK ANALYSIS • OPTIONAL OSV LOOKUP", style = MaterialTheme.typography.labelMedium)
                            Text("APK stays local • Optional version-only query to OSV.dev", style = MaterialTheme.typography.bodySmall)
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
                            osvResult?.advisories?.forEach { advisory ->
                                item(key = "osv-" + advisory.id) {
                                    Card { Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                                        Text("OSV • " + advisory.id, style = MaterialTheme.typography.titleMedium)
                                        Text(advisory.summary)
                                        advisory.severity?.let { Text("CVSS: " + it, style = MaterialTheme.typography.bodySmall) }
                                        advisory.affected.forEach { Text("Affected: " + it, style = MaterialTheme.typography.bodySmall) }
                                        if (advisory.aliases.isNotEmpty()) Text("Aliases: " + advisory.aliases.joinToString())
                                        advisory.modified?.let { Text("Last modified: " + it, style = MaterialTheme.typography.bodySmall) }
                                        advisory.references.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary) }
                                    } }
                                }
                            }
                            item {
                                Card { Column(Modifier.padding(15.dp)) {
                                    Text("ASSESSMENT RESULTS", style = MaterialTheme.typography.titleLarge)
                                    Text(r.fileName)
                                    Text("${r.inspectedEntries} archive entries inspected • ${r.riskCount} review findings")
                                    Text("${r.dependencies.size} exact Maven coordinates available for SBOM export", style = MaterialTheme.typography.bodySmall)
                                    OutlinedButton(
                                        onClick = { sbomExporter.launch("vantage-shield-sbom.json") },
                                        enabled = !busy,
                                        modifier = Modifier.fillMaxWidth()
                                    ) { Text("EXPORT CYCLONEDX SBOM") }
                                    OutlinedButton(
                                        onClick = {
                                            osvBusy = true
                                            osvError = null
                                            osvResult = null
                                            scope.launch {
                                                try {
                                                    osvResult = withContext(Dispatchers.IO) { OsvClient.check(r.dependencies) }
                                                } catch (e: Exception) {
                                                    osvError = e.message ?: "OSV lookup failed."
                                                } finally { osvBusy = false }
                                            }
                                        },
                                        enabled = !busy && !osvBusy && r.dependencies.isNotEmpty(),
                                        modifier = Modifier.fillMaxWidth()
                                    ) { Text(if (osvBusy) "CHECKING OSV…" else "CHECK OSV ADVISORIES (INTERNET)") }
                                    Text("This sends exact package names and versions to api.osv.dev. No APK, file contents, or personal data are uploaded.", style = MaterialTheme.typography.bodySmall)
                                    if (osvBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
                                    osvError?.let { Text("OSV STATUS UNKNOWN • " + it, color = MaterialTheme.colorScheme.error) }
                                    osvResult?.let { result ->
                                        val summary = if (result.advisories.isEmpty()) "No matching advisories were returned; this is not proof of safety." else result.advisories.size.toString() + " advisory record(s) returned."
                                        Text("OSV checked " + result.packagesChecked + " package(s) at " + result.checkedAt + ". " + summary, style = MaterialTheme.typography.bodySmall)
                                        if (result.truncated) Text("Result capped for safety; not all packages or advisories may be represented.")
                                    }
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
