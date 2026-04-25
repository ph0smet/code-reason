package io.github.blindhacker99.codereason.catalog.python

import io.github.blindhacker99.codereason.catalog.*
import io.github.blindhacker99.codereason.catalog.LanguageProfile.PYTHON
import io.github.blindhacker99.codereason.catalog.TaintKind.*
import io.github.blindhacker99.codereason.catalog.VulnClass.CMDI

object PythonCmdiCatalog : SourceSinkCatalog {
    override val vulnClass = CMDI
    override val language = PYTHON

    override val sources =
        listOf(
            TaintSpec(CMDI, PYTHON, "flask.request.args.get", SOURCE, "Flask query parameter"),
            TaintSpec(CMDI, PYTHON, "flask.request.form.get", SOURCE, "Flask form data"),
            TaintSpec(CMDI, PYTHON, "django.http.request.HttpRequest.GET.get", SOURCE, "Django GET parameter"),
            TaintSpec(CMDI, PYTHON, "django.http.request.HttpRequest.POST.get", SOURCE, "Django POST parameter"),
        )

    override val sinks =
        listOf(
            TaintSpec(CMDI, PYTHON, "os.system", SINK, "os.system command execution", paramIndex = 0),
            TaintSpec(CMDI, PYTHON, "os.popen", SINK, "os.popen command execution", paramIndex = 0),
            TaintSpec(CMDI, PYTHON, "subprocess.call", SINK, "subprocess.call", paramIndex = 0),
            TaintSpec(CMDI, PYTHON, "subprocess.run", SINK, "subprocess.run", paramIndex = 0),
            TaintSpec(CMDI, PYTHON, "subprocess.Popen", SINK, "subprocess.Popen", paramIndex = 0),
        )

    override val sanitizers =
        listOf(
            TaintSpec(CMDI, PYTHON, "shlex.quote", SANITIZER, "Shell argument quoting"),
            TaintSpec(CMDI, PYTHON, "shlex.split", SANITIZER, "Shell argument splitting"),
        )
}
