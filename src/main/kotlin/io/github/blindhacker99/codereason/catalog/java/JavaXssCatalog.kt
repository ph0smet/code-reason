package io.github.blindhacker99.codereason.catalog.java

import io.github.blindhacker99.codereason.catalog.*
import io.github.blindhacker99.codereason.catalog.LanguageProfile.JAVA
import io.github.blindhacker99.codereason.catalog.TaintKind.*
import io.github.blindhacker99.codereason.catalog.VulnClass.XSS

object JavaXssCatalog : SourceSinkCatalog {
    override val vulnClass = XSS
    override val language = JAVA

    override val sources =
        listOf(
            TaintSpec(XSS, JAVA, "javax.servlet.http.HttpServletRequest.getParameter", SOURCE, "Servlet request parameter"),
            TaintSpec(XSS, JAVA, "javax.servlet.http.HttpServletRequest.getQueryString", SOURCE, "Raw query string"),
            TaintSpec(XSS, JAVA, "javax.servlet.http.HttpServletRequest.getHeader", SOURCE, "HTTP request header"),
            TaintSpec(XSS, JAVA, "javax.servlet.http.HttpServletRequest.getPathInfo", SOURCE, "URL path info"),
        )

    override val sinks =
        listOf(
            TaintSpec(XSS, JAVA, "javax.servlet.http.HttpServletResponse.getWriter", SINK, "Response writer"),
            TaintSpec(XSS, JAVA, "java.io.PrintWriter.write", SINK, "PrintWriter write"),
            TaintSpec(XSS, JAVA, "java.io.PrintWriter.println", SINK, "PrintWriter println"),
            TaintSpec(XSS, JAVA, "java.io.PrintWriter.print", SINK, "PrintWriter print"),
        )

    override val sanitizers =
        listOf(
            TaintSpec(XSS, JAVA, "org.owasp.encoder.Encode.forHtml", SANITIZER, "OWASP HTML encoding"),
            TaintSpec(XSS, JAVA, "org.owasp.encoder.Encode.forJavaScript", SANITIZER, "OWASP JS encoding"),
            TaintSpec(XSS, JAVA, "org.springframework.web.util.HtmlUtils.htmlEscape", SANITIZER, "Spring HTML escape"),
        )
}
