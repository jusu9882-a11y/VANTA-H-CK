package dev.jusu.vantageshield

enum class Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO }
data class Finding(val title: String, val severity: Severity, val evidence: String, val recommendation: String)
data class ScanReport(
    val fileName: String,
    val findings: List<Finding>,
    val inspectedEntries: Int,
    val dependencies: List<DependencyCoordinate> = emptyList()
) {
    val riskCount: Int get() = findings.count { it.severity == Severity.CRITICAL || it.severity == Severity.HIGH || it.severity == Severity.MEDIUM }
}
