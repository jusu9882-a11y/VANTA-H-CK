# VANTAGE SHIELD

Standalone Android security assessment tool for the Vantage application.

## Current capabilities
- Import an APK through Android's Storage Access Framework; no broad storage permission.
- Inspect APK ZIP contents and DEX strings for high-signal indicators such as HTTP URLs and embedded private-key or credential-like markers.
- Decode the compiled Android binary manifest using an in-app parser and audit application flags, SDK target, declared permissions, and exported activities, services, receivers, providers, and aliases.\n- Perform cautious string-level cryptography/TLS triage for weak-algorithm and certificate-validation markers; identify bundled native libraries and dependency metadata as inventory leads.
- Show severity, evidence, and remediation guidance for findings.
- Run local Android device posture checks for API level, developer-options state (where readable), and Bluetooth/Wi-Fi adapter state.
- Open the built-in **SHIELD TERMINAL** for interactive local diagnostics: `help`, `status`, `device`, `refresh`, `version`, `clear`, and `exit`.
- Offline operation; the APK is analyzed locally and never uploaded.

## Manifest audit scope and limitations
The binary XML reader extracts common manifest string and typed attributes. Current rules flag release debuggability, cleartext traffic explicitly enabled, backup enabled, older target SDK values, and exported components without a component-level permission. Exported status alone is not proof of a vulnerability. Findings are triage signals and require manual review. Resource references, manifest-merger provenance, network security configuration contents, SDK-specific component semantics, and all permission protection levels are not yet fully resolved. A manifest that cannot be decoded is not silently treated as clean.

## Terminal safety
The terminal is a restricted diagnostic console, not an unrestricted Android/Linux shell. It accepts only documented built-in commands and does not execute arbitrary shell strings, require root, or provide network access.

## Safety boundaries
This release performs passive local APK inspection and non-invasive device posture checks. It does not exploit devices, intercept third-party traffic, bypass Android protections, or attack nearby networks. Dynamic Bluetooth/Wi-Fi protocol testing requires an explicitly paired, consented Vantage test device and a dedicated isolated test mode. Heuristic findings require manual validation and a clean scan is not a security certification.

## Build
Requires JDK 17 and Gradle 8.9.
```sh
gradle testDebugUnitTest assembleDebug
```
APK: `app/build/outputs/apk/debug/app-debug.apk`
