package io.github.blindhacker99.codereason.catalog.java

import io.github.blindhacker99.codereason.catalog.*
import io.github.blindhacker99.codereason.catalog.LanguageProfile.JAVA
import io.github.blindhacker99.codereason.catalog.TaintKind.*
import io.github.blindhacker99.codereason.catalog.VulnClass.CMDI

object JavaCmdiCatalog : SourceSinkCatalog {
    override val vulnClass = CMDI
    override val language = JAVA

    override val sources =
        listOf(
            TaintSpec(CMDI, JAVA, "javax.servlet.http.HttpServletRequest.getParameter", SOURCE, "Servlet request parameter"),
            TaintSpec(CMDI, JAVA, "javax.servlet.http.HttpServletRequest.getQueryString", SOURCE, "Raw query string"),
            TaintSpec(CMDI, JAVA, "javax.servlet.http.HttpServletRequest.getHeader", SOURCE, "HTTP request header"),
        )

    override val sinks =
        listOf(
            TaintSpec(CMDI, JAVA, "java.lang.Runtime.exec", SINK, "Runtime.exec command execution", paramIndex = 0),
            TaintSpec(CMDI, JAVA, "java.lang.ProcessBuilder.<init>", SINK, "ProcessBuilder construction"),
            TaintSpec(CMDI, JAVA, "java.lang.ProcessBuilder.command", SINK, "ProcessBuilder command"),
        )

    override val sanitizers =
        listOf(
            TaintSpec(CMDI, JAVA, "org.apache.commons.text.StringEscapeUtils.escapeXSI", SANITIZER, "Shell argument escaping"),
        )
}
