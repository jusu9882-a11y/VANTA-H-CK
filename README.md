# VANTAGE SHIELD

Standalone Android security assessment tool for the Vantage application.

## First release
- Import an APK through Android's Storage Access Framework; no broad storage permission.
- Inspect APK ZIP contents and DEX/manifest byte strings for high-signal security indicators.
- Show severity, evidence, and remediation guidance.
- Run local Android device posture checks for API level, developer-options state (where readable), and Bluetooth/Wi-Fi adapter state.
- Offline operation; the APK is analyzed locally and never uploaded.

## Safety boundaries
This release performs passive local APK inspection and non-invasive device posture checks. It does not exploit devices, intercept third-party traffic, bypass Android protections, or attack nearby networks. Dynamic Bluetooth/Wi-Fi protocol testing requires an explicitly paired, consented Vantage test device and a dedicated isolated test mode.

## Build
Requires JDK 17 and Gradle 8.9.
```sh
gradle testDebugUnitTest assembleDebug
```
APK: `app/build/outputs/apk/debug/app-debug.apk`
