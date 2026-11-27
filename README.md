# VANTAGE SHIELD

Standalone Android security assessment tool for the Vantage application.

## Current capabilities
- Import an APK through Android's Storage Access Framework; no broad storage permission.
- Inspect APK ZIP contents and DEX strings for high-signal indicators such as HTTP URLs and embedded private-key or credential-like markers.
- Structurally validate DEX headers, string/type/class tables, and inventory recognizable library namespaces from actual class definitions (for example OkHttp, Retrofit, Gson, Kotlin, AndroidX, and Bouncy Castle). Invalid DEX-like entries are reported as unavailable rather than silently trusted.
- Decode the compiled Android binary manifest using an in-app parser and audit application flags, SDK target, declared permissions, and exported activities, services, receivers, providers, and aliases.
- Perform cautious string-level cryptography/TLS triage for weak-algorithm and certificate-validation markers; identify bundled native libraries and dependency metadata as inventory leads.
- Show severity, evidence, and remediation guidance for findings.
- Run local Android device posture checks for API level, developer-options state (where readable), and Bluetooth/Wi-Fi adapter state.
- Open the built-in **SHIELD TERMINAL** for app-specific commands (`help`, `status`, `device`, `scan`, `findings`, `refresh`, `version`, `clear`, `exit`) and real read-only Android diagnostics (`id`, `whoami`, `uname`, `uptime`, `df`, `ps`, `ip addr`, `ip route`, and approved `getprop` values).
- Offline operation; the APK is analyzed locally and never uploaded.

## Manifest audit scope and limitations
The binary XML reader extracts common manifest string and typed attributes. Current rules flag release debuggability, cleartext traffic explicitly enabled, backup enabled, older target SDK values, and exported components without a component-level permission. Exported status alone is not proof of a vulnerability. Findings are triage signals and require manual review. Resource references, manifest-merger provenance, network security configuration contents, SDK-specific component semantics, and all permission protection levels are not yet fully resolved. A manifest that cannot be decoded is not silently treated as clean.

## Terminal commands and safety
The terminal is a restricted Android diagnostic command interpreter, not an unrestricted shell. App-specific commands read the current device posture and most recent APK assessment. System commands execute fixed `/system/bin/toybox` or `/system/bin/getprop` argument arrays directly through Android ProcessBuilder; no shell is invoked. The allowlist rejects arbitrary executables, command chaining, scripts, and unapproved property names. Commands run with the app UID and Android sandbox permissions, without root. System commands have a short timeout and bounded output. Network inspection commands only display local interface and route information; they do not scan or attack networks. The terminal uses a green-on-black colour-2 theme.

## Safety boundaries
This release performs passive local APK inspection and non-invasive device posture checks. It does not exploit devices, intercept third-party traffic, bypass Android protections, or attack nearby networks. Dynamic Bluetooth/Wi-Fi protocol testing requires an explicitly paired, consented Vantage test device and a dedicated isolated test mode. Heuristic findings require manual validation and a clean scan is not a security certification.

## Build
Requires JDK 17 and Gradle 8.9.
```sh
gradle testDebugUnitTest assembleDebug
```
APK: `app/build/outputs/apk/debug/app-debug.apk`
