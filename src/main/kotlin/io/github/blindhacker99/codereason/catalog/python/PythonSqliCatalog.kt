package io.github.blindhacker99.codereason.catalog.python

import io.github.blindhacker99.codereason.catalog.*
import io.github.blindhacker99.codereason.catalog.LanguageProfile.PYTHON
import io.github.blindhacker99.codereason.catalog.TaintKind.*
import io.github.blindhacker99.codereason.catalog.VulnClass.SQLI

object PythonSqliCatalog : SourceSinkCatalog {
    override val vulnClass = SQLI
    override val language = PYTHON

    override val sources =
        listOf(
            TaintSpec(SQLI, PYTHON, "flask.request.args.get", SOURCE, "Flask query parameter"),
            TaintSpec(SQLI, PYTHON, "flask.request.form.get", SOURCE, "Flask form data"),
            TaintSpec(SQLI, PYTHON, "flask.request.values.get", SOURCE, "Flask combined params"),
            TaintSpec(SQLI, PYTHON, "django.http.request.HttpRequest.GET.get", SOURCE, "Django GET parameter"),
            TaintSpec(SQLI, PYTHON, "django.http.request.HttpRequest.POST.get", SOURCE, "Django POST parameter"),
        )

    override val sinks =
        listOf(
            TaintSpec(SQLI, PYTHON, "sqlite3.Cursor.execute", SINK, "SQLite execute", paramIndex = 0),
            TaintSpec(SQLI, PYTHON, "psycopg2.cursor.execute", SINK, "PostgreSQL execute", paramIndex = 0),
            TaintSpec(SQLI, PYTHON, "MySQLdb.cursors.BaseCursor.execute", SINK, "MySQL execute", paramIndex = 0),
            TaintSpec(SQLI, PYTHON, "sqlalchemy.text", SINK, "SQLAlchemy raw text query", paramIndex = 0),
        )

    override val sanitizers =
        listOf(
            TaintSpec(SQLI, PYTHON, "sqlalchemy.bindparam", SANITIZER, "SQLAlchemy bound parameter"),
        )
}
