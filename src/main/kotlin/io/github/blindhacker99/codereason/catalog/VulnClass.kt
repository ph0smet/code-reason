package io.github.blindhacker99.codereason.catalog

enum class VulnClass(val cweId: Int, val cweName: String) {
    SQLI(89, "SQL Injection"),
    XSS(79, "Cross-site Scripting"),
    CMDI(78, "OS Command Injection"),
}

enum class LanguageProfile { JAVA, PYTHON }

enum class TaintKind { SOURCE, SINK, SANITIZER }

data class TaintSpec(
    val vulnClass: VulnClass,
    val language: LanguageProfile,
    val fqn: String,
    val kind: TaintKind,
    val description: String,
    val paramIndex: Int? = null,
)

interface SourceSinkCatalog {
    val vulnClass: VulnClass
    val language: LanguageProfile
    val sources: List<TaintSpec>
    val sinks: List<TaintSpec>
    val sanitizers: List<TaintSpec>
}
