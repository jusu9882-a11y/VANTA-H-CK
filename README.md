# VANTAGE SHIELD

Standalone Android security assessment tool for the Vantage application.

## First release
- Import an APK through Android's Storage Access Framework; no broad storage permission.
- Inspect APK ZIP contents and DEX/manifest byte strings for high-signal security indicators.
- Show severity, evidence, and remediation guidance.
- Run local Android device posture checks for API level, developer-options state (where readable), and Bluetooth/Wi-Fi adapter state.
- Open the built-in **SHIELD TERMINAL** for interactive local diagnostics: `help`, `status`, `device`, `refresh`, `version`, `clear`, and `exit`.
- Offline operation; the APK is analyzed locally and never uploaded.

## Terminal safety
The terminal is a restricted diagnostic console, not an unrestricted Android/Linux shell. It accepts only documented built-in commands and does not execute arbitrary shell strings, require root, or provide network access.

## Safety boundaries
This release performs passive local APK inspection and non-invasive device posture checks. It does not exploit devices, intercept third-party traffic, bypass Android protections, or attack nearby networks. Dynamic Bluetooth/Wi-Fi protocol testing requires an explicitly paired, consented Vantage test device and a dedicated isolated test mode. Heuristic APK findings require manual validation and a clean scan is not a security certification.

## Build
Requires JDK 17 and Gradle 8.9.
```sh
gradle testDebugUnitTest assembleDebug
```
APK: `app/build/outputs/apk/debug/app-debug.apk`
