package io.github.blindhacker99.codereason.catalog.java

import io.github.blindhacker99.codereason.catalog.*
import io.github.blindhacker99.codereason.catalog.LanguageProfile.JAVA
import io.github.blindhacker99.codereason.catalog.TaintKind.*
import io.github.blindhacker99.codereason.catalog.VulnClass.SQLI

object JavaSqliCatalog : SourceSinkCatalog {
    override val vulnClass = SQLI
    override val language = JAVA

    override val sources =
        listOf(
            TaintSpec(SQLI, JAVA, "javax.servlet.http.HttpServletRequest.getParameter", SOURCE, "Servlet request parameter"),
            TaintSpec(SQLI, JAVA, "javax.servlet.http.HttpServletRequest.getQueryString", SOURCE, "Raw query string"),
            TaintSpec(SQLI, JAVA, "javax.servlet.http.HttpServletRequest.getHeader", SOURCE, "HTTP request header"),
            TaintSpec(SQLI, JAVA, "javax.servlet.http.HttpServletRequest.getCookies", SOURCE, "HTTP cookies"),
            TaintSpec(SQLI, JAVA, "javax.servlet.http.HttpServletRequest.getPathInfo", SOURCE, "URL path info"),
        )

    override val sinks =
        listOf(
            TaintSpec(SQLI, JAVA, "java.sql.Statement.executeQuery", SINK, "JDBC executeQuery", paramIndex = 0),
            TaintSpec(SQLI, JAVA, "java.sql.Statement.executeUpdate", SINK, "JDBC executeUpdate", paramIndex = 0),
            TaintSpec(SQLI, JAVA, "java.sql.Statement.execute", SINK, "JDBC execute", paramIndex = 0),
            TaintSpec(SQLI, JAVA, "java.sql.Connection.prepareStatement", SINK, "JDBC prepareStatement", paramIndex = 0),
        )

    override val sanitizers =
        listOf(
            TaintSpec(SQLI, JAVA, "java.sql.PreparedStatement.setString", SANITIZER, "Parameterized query binding"),
            TaintSpec(SQLI, JAVA, "java.sql.PreparedStatement.setInt", SANITIZER, "Parameterized query binding"),
            TaintSpec(SQLI, JAVA, "java.sql.PreparedStatement.setLong", SANITIZER, "Parameterized query binding"),
            TaintSpec(SQLI, JAVA, "java.sql.PreparedStatement.setObject", SANITIZER, "Parameterized query binding"),
        )
}
