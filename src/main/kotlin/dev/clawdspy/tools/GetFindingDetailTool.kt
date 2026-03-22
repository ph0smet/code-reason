package dev.clawdspy.tools

import de.fraunhofer.aisec.cpg.passes.Description
import dev.clawdspy.catalog.VulnClass
import dev.clawdspy.model.Finding
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class GetFindingDetailPayload(
    @Description("The finding ID from a previous spy_scan_injections call.")
    val findingId: String,
)

@Serializable
data class FindingDetail(
    val finding: Finding,
    val cweDescription: String,
    val remediation: String,
)

fun Server.addGetFindingDetailTool() {
    addTool<GetFindingDetailPayload>(
        name = "spy_get_finding_detail",
        description =
            "Get detailed information about a specific finding including CWE description and remediation advice.",
    ) { payload ->
        val finding = lastScanFindings.find { it.id == payload.findingId }
            ?: throw IllegalArgumentException(
                "Finding not found: ${payload.findingId}. Run spy_scan_injections first."
            )

        val vulnClass = VulnClass.entries.find { it.name.equals(finding.vulnClass, ignoreCase = true) }

        val detail = FindingDetail(
            finding = finding,
            cweDescription = getCweDescription(vulnClass),
            remediation = getRemediation(vulnClass),
        )

        CallToolResult(
            content = listOf(TextContent(Json.encodeToString(detail)))
        )
    }
}

private fun getCweDescription(vulnClass: VulnClass?): String {
    return when (vulnClass) {
        VulnClass.SQLI ->
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'). " +
                "The application constructs all or part of an SQL command using externally-influenced input " +
                "from an upstream component, but it does not neutralize or incorrectly neutralizes special " +
                "elements that could modify the intended SQL command."
        VulnClass.XSS ->
            "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'). " +
                "The application does not neutralize or incorrectly neutralizes user-controllable input " +
                "before it is placed in output that is used as a web page served to other users."
        VulnClass.CMDI ->
            "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'). " +
                "The application constructs all or part of an OS command using externally-influenced input " +
                "from an upstream component, but it does not neutralize or incorrectly neutralizes special " +
                "elements that could modify the intended OS command."
        null -> "Unknown vulnerability class."
    }
}

private fun getRemediation(vulnClass: VulnClass?): String {
    return when (vulnClass) {
        VulnClass.SQLI ->
            "Use parameterized queries (PreparedStatement) instead of string concatenation. " +
                "For Java: use PreparedStatement with ? placeholders and setString/setInt/etc. " +
                "For Python: use parameterized queries with cursor.execute(query, params). " +
                "Never concatenate user input directly into SQL strings."
        VulnClass.XSS ->
            "Encode all user-controlled output using context-appropriate encoding. " +
                "For Java: use OWASP Encoder (Encode.forHtml) or Spring's HtmlUtils.htmlEscape. " +
                "For Python: use markupsafe.escape or Django's auto-escaping. " +
                "Avoid using render_template_string, mark_safe, or Markup with user input."
        VulnClass.CMDI ->
            "Avoid passing user input to OS commands. If unavoidable, use allowlists for valid inputs. " +
                "For Java: use ProcessBuilder with argument arrays instead of Runtime.exec(String). " +
                "For Python: use subprocess with shell=False and pass arguments as a list. " +
                "Use shlex.quote() to escape arguments when shell=True is required."
        null -> "Review the finding and apply appropriate input validation and output encoding."
    }
}
